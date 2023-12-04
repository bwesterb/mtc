package mtc

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// Public parameters of a Merkle Tree CA
type CAParams struct {
	IssuerId           string
	PublicKey          Verifier
	StartTime          uint64
	BatchDuration      uint64
	Lifetime           uint64
	ValidityWindowSize uint64
	StorageWindowSize  uint64
	HttpServer         string
}

const (
	HashLen = 32
)

type ClaimType uint16

const (
	DnsClaimType ClaimType = iota
	DnsWildcardClaimType
	Ipv4ClaimType
	Ipv6ClaimType
)

// List of claims.
type Claims struct {
	DNS         []string
	DNSWildcard []string
	IPv4        []net.IP
	IPv6        []net.IP
	Unknown     []UnknownClaim
}

// Represents a claim we do not how to interpret.
type UnknownClaim struct {
	Type ClaimType
	Info []byte
}

type SubjectType uint16

const (
	TLSSubjectType SubjectType = iota
)

type SubjectBase interface {
	Type() SubjectType
	Info() []byte
}

type AbridgedSubject interface {
	SubjectBase
}

type Subject interface {
	SubjectBase
	Abridge() AbridgedSubject
}

type TLSSubject struct {
	pk     Verifier
	packed []byte
}

// Used for either an unknown (abridged) subject
type UnknownSubject struct {
	typ  SubjectType
	info []byte
}

type Assertion struct {
	Subject Subject
	Claims  Claims
}

type AbridgedAssertion struct {
	Subject AbridgedSubject
	Claims  Claims
}

// Copy of tls.SignatureScheme to prevent cycling dependencies
type SignatureScheme uint16

const (
	TLSPSSWithSHA256          SignatureScheme = 0x0804
	TLSPSSWithSHA384          SignatureScheme = 0x0805
	TLSPSSWithSHA512          SignatureScheme = 0x0806
	TLSECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	TLSECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	TLSECDSAWithP521AndSHA512 SignatureScheme = 0x0603
	TLSEd25519                SignatureScheme = 0x0807

	// Just for testing we use round 3 Dilithium5 with a codepoint in the
	// private use region. For production SPHINCS⁺-128s would be a better
	// choice.
	TLSDilitihium5r3 SignatureScheme = 0xfe3c
)

type AbridgedTLSSubject struct {
	SignatureScheme SignatureScheme
	PublicKeyHash   [HashLen]byte
}

type BikeshedCertificate struct {
	Assertion Assertion
	Proof     Proof
}

type ProofType uint16

const (
	MerkleTreeProofType ProofType = iota
)

type TrustAnchor interface {
	ProofType() ProofType
	Info() []byte
}

type MerkleTreeTrustAnchor struct {
	issuerId    string
	batchNumber uint32
}

type UnknownTrustAnchor struct {
	typ  ProofType
	info []byte
}

type Proof interface {
	TrustAnchor() TrustAnchor
	Info() []byte
}

type MerkleTreeProof struct {
	anchor *MerkleTreeTrustAnchor
	index  uint64
	path   []byte
}

type UnknownProof struct {
	anchor *UnknownTrustAnchor
	info   []byte
}

type ValidityWindow struct {
	BatchNumber uint32
	TreeHeads   []byte
}

type SignedValidityWindow struct {
	ValidityWindow
	Signature []byte
}

func (t *MerkleTreeTrustAnchor) ProofType() ProofType {
	return MerkleTreeProofType
}

func (t *MerkleTreeTrustAnchor) Info() []byte {
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(t.issuerId))
	})
	b.AddUint32(t.batchNumber)
	ret, err := b.Bytes()
	if err != nil {
		// Can only happen if issuerId is too long, but we checked for this.
		panic(err)
	}
	return ret
}

func (t *UnknownTrustAnchor) ProofType() ProofType {
	return t.typ
}

func (t *UnknownTrustAnchor) Info() []byte {
	return t.info
}

func (p *MerkleTreeProof) TrustAnchor() TrustAnchor {
	return p.anchor
}

func (p *MerkleTreeProof) Info() []byte {
	var b cryptobyte.Builder
	b.AddUint64(p.index)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(p.path)
	})
	ret, err := b.Bytes()
	if err != nil {
		// Can only happen if path is too long, but we checked for this.
		panic(err)
	}
	return ret
}

func (p *UnknownProof) TrustAnchor() TrustAnchor {
	return p.anchor
}

func (p *UnknownProof) Info() []byte {
	return p.info
}

type Batch struct {
	CA     *CAParams
	Number uint32
}

// Range of batch numbers Begin, …, End-1.
type BatchRange struct {
	Begin uint32
	End   uint32
}

func (r BatchRange) Len() int {
	return int(r.End) - int(r.Begin)
}

// Returns whether each batch in the range is after the given batch
func (r BatchRange) AreAllPast(batch uint32) bool {
	if r.Begin == r.End {
		return true
	}
	return batch < r.Begin
}

// Returns whether r contains the batch with the given number.
func (r BatchRange) Contains(batch uint32) bool {
	return r.Begin <= batch && batch < r.End
}

func (r BatchRange) String() string {
	if r.Begin == r.End {
		return "⌀"
	}
	return fmt.Sprintf("%d,…,%d", r.Begin, r.End-1)
}

// Merkle tree built upon the assertions of a batch.
type Tree struct {
	// Concatenation of nodes left-to-right, bottom-to-top, so for
	//
	//        level 2:               t20
	//                          _____/ \_____
	//                         /             \
	//        level 1:       t10             t11
	//                       / \             / \
	//                      /   \           /   \
	//        level 0:   t00     t01     t02    t03
	//                    |       |       |
	//                    a0      a1      a2
	//
	// we would have buf be the concatenation of  t00 t01 t02 t03 t10 t11 t20.
	buf []byte

	nLeaves uint64 // Number of assertions
}

// Write the tree to w
func (t *Tree) WriteTo(w io.Writer) error {
	var b cryptobyte.Builder
	b.AddUint64(t.nLeaves)
	buf, err := b.Bytes()
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	if err != nil {
		return err
	}
	_, err = w.Write(t.buf)
	if err != nil {
		return err
	}
	return nil
}

func (c *BikeshedCertificate) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	buf, err := c.Assertion.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal Assertion: %w", err)
	}
	b.AddBytes(buf)
	b.AddUint16(uint16(c.Proof.TrustAnchor().ProofType()))
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(c.Proof.TrustAnchor().Info())
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(c.Proof.Info())
	})
	return b.Bytes()
}

func (c *BikeshedCertificate) UnmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)
	err := c.Assertion.unmarshal(&s)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal Assertion: %w", err)
	}
	var (
		typ        ProofType
		proofInfo  cryptobyte.String
		anchorInfo cryptobyte.String
	)
	if !s.ReadUint16((*uint16)(&typ)) ||
		!s.ReadUint8LengthPrefixed(&anchorInfo) ||
		!s.ReadUint16LengthPrefixed(&proofInfo) {
		return ErrTruncated
	}
	if !s.Empty() {
		return ErrExtraBytes
	}
	switch typ {
	case MerkleTreeProofType:
		proof := &MerkleTreeProof{
			anchor: &MerkleTreeTrustAnchor{},
		}
		var issuerId []byte
		if !anchorInfo.ReadUint8LengthPrefixed((*cryptobyte.String)(&issuerId)) ||
			!anchorInfo.ReadUint32(&proof.anchor.batchNumber) {
			return ErrTruncated
		}
		proof.anchor.issuerId = string(issuerId)
		if !anchorInfo.Empty() {
			return ErrExtraBytes
		}
		if !proofInfo.ReadUint64(&proof.index) ||
			!proofInfo.ReadUint16LengthPrefixed((*cryptobyte.String)(&proof.path)) {
			return ErrTruncated
		}
		if !proofInfo.Empty() {
			return ErrExtraBytes
		}
		c.Proof = proof
		return nil
	}
	c.Proof = &UnknownProof{
		anchor: &UnknownTrustAnchor{
			typ:  typ,
			info: []byte(anchorInfo),
		},
		info: []byte(proofInfo),
	}
	return nil
}

// Batches that are expected to be available at this CA, at the given time.
// The last few might not yet have been published.
func (p *CAParams) StoredBatches(dt time.Time) BatchRange {
	ts := dt.Unix()
	if ts < int64(p.StartTime) {
		return BatchRange{} // none
	}
	currentNumber := (ts - int64(p.StartTime)) / int64(p.BatchDuration)
	start := currentNumber - int64(p.StorageWindowSize)
	if start < 0 {
		start = 0
	}
	return BatchRange{
		Begin: uint32(start),
		End:   uint32(currentNumber),
	}
}

// Batches that are non-expired, and either issued or ready, at the given time.
func (p *CAParams) ActiveBatches(dt time.Time) BatchRange {
	ts := dt.Unix()
	if ts < int64(p.StartTime) {
		return BatchRange{} // none
	}
	currentNumber := (ts - int64(p.StartTime)) / int64(p.BatchDuration)
	start := currentNumber - int64(p.ValidityWindowSize)
	if start < 0 {
		start = 0
	}
	return BatchRange{
		Begin: uint32(start),
		End:   uint32(currentNumber),
	}
}

func (p *CAParams) MarshalBinary() ([]byte, error) {
	// TODO add struct to I-D
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(p.IssuerId))
	})
	b.AddUint16(uint16(p.PublicKey.Scheme()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(p.PublicKey.Bytes())
	})
	b.AddUint64(p.StartTime)
	b.AddUint64(p.BatchDuration)
	b.AddUint64(p.Lifetime)
	b.AddUint64(p.ValidityWindowSize)
	b.AddUint64(p.StorageWindowSize)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(p.HttpServer))
	})
	return b.Bytes()
}

func (p *CAParams) UnmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)
	var (
		issuerBuf     []byte
		pkBuf         []byte
		httpServerBuf []byte
		sigScheme     SignatureScheme
		err           error
	)

	if !s.ReadUint8LengthPrefixed((*cryptobyte.String)(&issuerBuf)) ||
		!s.ReadUint16((*uint16)(&sigScheme)) ||
		!s.ReadUint16LengthPrefixed((*cryptobyte.String)(&pkBuf)) ||
		!s.ReadUint64(&p.StartTime) ||
		!s.ReadUint64(&p.BatchDuration) ||
		!s.ReadUint64(&p.Lifetime) ||
		!s.ReadUint64(&p.ValidityWindowSize) ||
		!s.ReadUint64(&p.StorageWindowSize) ||
		!s.ReadUint16LengthPrefixed((*cryptobyte.String)(&httpServerBuf)) {
		return ErrTruncated
	}

	if !s.Empty() {
		return ErrExtraBytes
	}

	p.IssuerId = string(issuerBuf)
	p.HttpServer = string(httpServerBuf)
	p.PublicKey, err = UnmarshalVerifier(sigScheme, pkBuf)
	if err != nil {
		return err
	}

	return p.Validate()
}

func (p *CAParams) Validate() error {
	if len(p.IssuerId) > 32 {
		return errors.New("issuer_id must be 32 bytes or less")
	}
	if len(p.IssuerId) == 0 {
		return errors.New("issuer_id can't be empty")
	}
	if p.Lifetime%p.BatchDuration != 0 {
		return errors.New("lifetime must be a multiple of batch_duration")
	}
	if p.ValidityWindowSize != p.Lifetime/p.BatchDuration {
		return errors.New("validity_window_size ≠ lifetime / batch_duration")
	}
	if p.StorageWindowSize < 2*p.ValidityWindowSize {
		return errors.New("storage_window_size < 2*validity_window_size")
	}
	return nil
}

// Returns the roots of the validity window prior the epoch.
func (p *CAParams) PreEpochRoots() []byte {
	b := Batch{
		Number: 0,
		CA:     p,
	}
	ret := make([]byte, int(p.ValidityWindowSize)*HashLen)
	if err := b.hashEmpty(ret[:], 0, 0); err != nil {
		panic(err)
	}
	for i := 1; i < int(p.ValidityWindowSize); i++ {
		copy(ret[i*HashLen:(i+1)*HashLen], ret[0:HashLen])
	}
	return ret
}

func (w *ValidityWindow) unmarshal(s *cryptobyte.String, p *CAParams) error {
	toRead := int(HashLen * p.ValidityWindowSize)
	if !s.ReadUint32(&w.BatchNumber) || !s.ReadBytes(&w.TreeHeads, toRead) {
		return ErrTruncated
	}

	return nil
}

func (w *SignedValidityWindow) UnmarshalBinary(data []byte, p *CAParams) error {
	s := cryptobyte.String(data)
	err := w.ValidityWindow.unmarshal(&s, p)
	if err != nil {
		return err
	}
	if !s.ReadUint16LengthPrefixed((*cryptobyte.String)(&w.Signature)) {
		return ErrTruncated
	}
	if !s.Empty() {
		return ErrExtraBytes
	}
	return nil
}

func (w *ValidityWindow) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint32(w.BatchNumber)
	b.AddBytes(w.TreeHeads)
	return b.Bytes()
}

func (w *SignedValidityWindow) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	window, err := w.ValidityWindow.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.AddBytes(window)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(w.Signature)
	})
	return b.Bytes()
}

// Returns the corresponding marshalled LabeledValdityWindow, which
// is signed by the CA.
func (w *ValidityWindow) LabeledValdityWindow(ca *CAParams) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddBytes([]byte("Merkle Tree Crts ValidityWindow\000"))
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(ca.IssuerId))
	})
	buf, err := w.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.AddBytes(buf)
	return b.Bytes()
}

// Returns TreeHeads from the previous batch's TreeHeads and the new root.
func (p *CAParams) newTreeHeads(prevHeads, root []byte) ([]byte, error) {
	expected := HashLen * p.ValidityWindowSize
	if len(prevHeads) != int(expected) {
		return nil, fmt.Errorf(
			"Expected prevHeads to be %d bytes; got %d bytes instead",
			expected,
			len(prevHeads),
		)
	}
	if len(root) != HashLen {
		return nil, fmt.Errorf(
			"Expected root to be %d bytes; got %d bytes instead",
			expected,
			len(root),
		)
	}
	return append(prevHeads[HashLen:len(prevHeads)], root...), nil
}

func (batch *Batch) SignValidityWindow(signer Signer, prevHeads []byte,
	root []byte) (SignedValidityWindow, error) {
	newHeads, err := batch.CA.newTreeHeads(prevHeads, root)
	if err != nil {
		return SignedValidityWindow{}, err
	}
	w := SignedValidityWindow{
		ValidityWindow: ValidityWindow{
			BatchNumber: batch.Number,
			TreeHeads:   newHeads,
		},
	}
	toSign, err := w.ValidityWindow.LabeledValdityWindow(batch.CA)
	if err != nil {
		return SignedValidityWindow{}, fmt.Errorf(
			"computing LabeledValidityWindow: %w",
			err,
		)
	}
	w.Signature = signer.Sign(toSign)
	return w, nil
}

func NewTLSSubject(scheme SignatureScheme, pk crypto.PublicKey) (*TLSSubject, error) {
	ver, err := NewVerifier(scheme, pk)
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint16(uint16(scheme))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ver.Bytes())
	})
	packed, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	return &TLSSubject{
		pk:     ver,
		packed: packed,
	}, nil
}

func (s *TLSSubject) Verifier() (Verifier, error) {
	if s.pk != nil {
		return s.pk, nil
	}

	ss := cryptobyte.String(s.packed)
	var (
		scheme    SignatureScheme
		publicKey cryptobyte.String
	)
	if !ss.ReadUint16((*uint16)(&scheme)) ||
		!ss.ReadUint16LengthPrefixed(&publicKey) {
		return nil, ErrTruncated
	}
	if !ss.Empty() {
		return nil, ErrExtraBytes
	}

	pk, err := UnmarshalVerifier(scheme, []byte(publicKey))
	if err != nil {
		return nil, err
	}

	s.pk = pk
	return pk, nil
}

func (s SubjectType) String() string {
	switch s {
	case TLSSubjectType:
		return "TLS"
	default:
		return fmt.Sprintf("SubjectType(%d)", s)
	}
}

func (s *TLSSubject) Type() SubjectType { return TLSSubjectType }

func (s *TLSSubject) Info() []byte {
	return s.packed
}

func (s *TLSSubject) Abridge() AbridgedSubject {
	ss := cryptobyte.String(s.packed)
	var (
		scheme    SignatureScheme
		publicKey cryptobyte.String
	)
	if !ss.ReadUint16((*uint16)(&scheme)) ||
		!ss.ReadUint16LengthPrefixed(&publicKey) {
		panic(ErrTruncated)
	}
	return &AbridgedTLSSubject{
		PublicKeyHash:   sha256.Sum256([]byte(publicKey)),
		SignatureScheme: scheme,
	}
}

func (s *AbridgedTLSSubject) Type() SubjectType { return TLSSubjectType }

func (s *AbridgedTLSSubject) Info() []byte {
	var b cryptobyte.Builder
	b.AddUint16(uint16(s.SignatureScheme))
	b.AddBytes(s.PublicKeyHash[:])
	buf, _ := b.Bytes()
	return buf
}

func (s *UnknownSubject) Type() SubjectType { return s.typ }
func (s *UnknownSubject) Info() []byte      { return s.info }
func (s *UnknownSubject) Abridge() AbridgedSubject {
	panic("Can't abridge unknown subject")
}

func (a *Assertion) Abridge() (ret AbridgedAssertion) {
	ret.Claims = a.Claims
	ret.Subject = a.Subject.Abridge()
	return
}

func (a *Assertion) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(uint16(a.Subject.Type()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // subject_info
		b.AddBytes(a.Subject.Info())
	})
	claims, err := a.Claims.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(claims)
	})
	return b.Bytes()
}

func (a *Assertion) UnmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)
	err := a.unmarshal(&s)
	if err != nil {
		return err
	}
	if !s.Empty() {
		return ErrExtraBytes
	}
	return nil
}

func (a *Assertion) unmarshal(s *cryptobyte.String) error {
	var (
		subjectType SubjectType
		subjectInfo cryptobyte.String
		claims      cryptobyte.String
	)
	if !s.ReadUint16((*uint16)(&subjectType)) ||
		!s.ReadUint16LengthPrefixed(&subjectInfo) ||
		!s.ReadUint16LengthPrefixed(&claims) {
		return ErrTruncated
	}

	if err := a.Claims.UnmarshalBinary([]byte(claims)); err != nil {
		return fmt.Errorf("Failed to unmarshal claims: %w", err)
	}

	switch subjectType {
	case TLSSubjectType:
		a.Subject = &TLSSubject{
			packed: []byte(subjectInfo),
		}
	default:
		a.Subject = &UnknownSubject{
			typ:  subjectType,
			info: []byte(subjectInfo),
		}
	}

	return nil
}

func (a *AbridgedAssertion) maxSize() int {
	return (65535+2)*2 + 2
}

func (a *AbridgedAssertion) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(uint16(a.Subject.Type()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // abridged_subject_info
		b.AddBytes(a.Subject.Info())
	})
	claims, err := a.Claims.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(claims)
	})
	return b.Bytes()
}

func (a *AbridgedAssertion) UnmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)
	err := a.unmarshal(&s)
	if err != nil {
		return err
	}
	if !s.Empty() {
		return ErrExtraBytes
	}
	return nil
}

func (a *AbridgedAssertion) unmarshal(s *cryptobyte.String) error {
	var (
		subjectType SubjectType
		subjectInfo cryptobyte.String
		claims      cryptobyte.String
	)
	if !s.ReadUint16((*uint16)(&subjectType)) ||
		!s.ReadUint16LengthPrefixed(&subjectInfo) ||
		!s.ReadUint16LengthPrefixed(&claims) {
		return ErrTruncated
	}

	if err := a.Claims.UnmarshalBinary([]byte(claims)); err != nil {
		return fmt.Errorf("Failed to unmarshal claims: %w", err)
	}

	switch subjectType {
	case TLSSubjectType:
		var (
			pkHash  []byte
			subject AbridgedTLSSubject
		)
		if !subjectInfo.ReadUint16((*uint16)(&subject.SignatureScheme)) ||
			!subjectInfo.ReadBytes(&pkHash, HashLen) {
			return ErrTruncated
		}
		if !subjectInfo.Empty() {
			return ErrExtraBytes
		}
		copy(subject.PublicKeyHash[:], pkHash)
		a.Subject = &subject
	default:
		a.Subject = &UnknownSubject{
			typ:  subjectType,
			info: []byte(subjectInfo),
		}
	}

	return nil
}

// Return root of the tree
func (t *Tree) Root() []byte {
	return t.buf[len(t.buf)-HashLen : len(t.buf)]
}

// Return authentication path proving that the leaf at the given index
// is included in the Merkle tree.
func (t *Tree) AuthenticationPath(index uint64) ([]byte, error) {
	if index >= t.nLeaves {
		return nil, errors.New("Tree index out of range")
	}

	ret := bytes.Buffer{}
	offset := 0
	nNodes := t.nLeaves
	for nNodes != 1 {
		index ^= 1 // index of sibling
		start := offset + int(HashLen*index)
		_, _ = ret.Write(t.buf[start : start+HashLen])

		// Account for the empty node
		if nNodes&1 == 1 {
			nNodes++
		}

		offset += HashLen * int(nNodes)
		index >>= 1
		nNodes >>= 1
	}

	return ret.Bytes(), nil
}

// Reads a stream of AbridgedAssertions from in, hashes them, and
// returns the concatenated hashes.
func (batch *Batch) hashLeaves(r io.Reader) ([]byte, error) {
	ret := &bytes.Buffer{}

	// First read all abridged assertions and hash them.
	var index uint64
	hash := make([]byte, HashLen)

	err := unmarshal(r, func(aa *AbridgedAssertion) error {
		err := aa.Hash(hash, batch, index)
		if err != nil {
			return err
		}
		_, _ = ret.Write(hash)
		index++
		return nil
	})

	if err != nil {
		return nil, err
	}

	return ret.Bytes(), nil
}

// Check validity of authentication path.
//
// Return nil on valid authentication path.
func (batch *Batch) VerifyAuthenticationPath(index uint64, path, root []byte,
	aa *AbridgedAssertion) error {
	h := make([]byte, HashLen)
	if err := aa.Hash(h[:], batch, index); err != nil {
		return err
	}

	level := uint8(0)
	var left, right []byte
	for len(path) != 0 {
		if len(path) < HashLen {
			return ErrTruncated
		}

		left, right, path = h, path[:HashLen], path[HashLen:]
		if index&1 == 1 {
			left, right = right, left
		}

		level++
		index >>= 1

		batch.hashNode(h, left, right, index, level)
	}

	if index != 0 {
		return fmt.Errorf("Authentication path too short")
	}

	if !bytes.Equal(root, h) {
		return fmt.Errorf("Authentication path invalid")
	}

	return nil
}

func (batch *Batch) hashNode(out, left, right []byte, index uint64,
	level uint8) error {
	var b cryptobyte.Builder

	b.AddUint8(1)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(batch.CA.IssuerId))
	})
	b.AddUint32(batch.Number)
	b.AddUint64(index)
	b.AddUint8(level)
	b.AddBytes(left)
	b.AddBytes(right)
	buf, err := b.Bytes()
	if err != nil {
		return err
	}
	h := sha256.New()
	_, _ = h.Write(buf)
	h.Sum(out[:0])

	return nil

}

func (batch *Batch) hashEmpty(out []byte, index uint64, level uint8) error {
	var b cryptobyte.Builder
	b.AddUint8(0)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(batch.CA.IssuerId))
	})
	b.AddUint32(batch.Number)
	b.AddUint64(index)
	b.AddUint8(level)
	buf, err := b.Bytes()
	if err != nil {
		return err
	}
	h := sha256.New()
	_, _ = h.Write(buf)
	h.Sum(out[:0])
	return nil
}

// Compute Merkle tree from a stream of AbridgedAssertion from in.
func (batch *Batch) ComputeTree(r io.Reader) (*Tree, error) {
	// First hash the leaves
	leaves, err := batch.hashLeaves(r)
	if err != nil {
		return nil, fmt.Errorf("HashLeaves: %w", err)
	}

	nLeaves := uint64(len(leaves)) / uint64(HashLen)
	buf := bytes.NewBuffer(leaves)

	if nLeaves == 0 {
		tree := &Tree{
			nLeaves: 0,
			buf:     make([]byte, HashLen),
		}
		if err := batch.hashEmpty(tree.buf[:], 0, 0); err != nil {
			return nil, err
		}
		return tree, nil
	}

	// Hash up the tree
	h := make([]byte, 32)
	var (
		level  uint8 = 0
		offset int   = 0 // offset of current level in buf
	)

	nNodes := nLeaves
	for nNodes != 1 {
		// Add empty node if number of leaves on this level is odd
		if nNodes&1 == 1 {
			if err := batch.hashEmpty(h, nNodes, level); err != nil {
				return nil, err
			}
			_, _ = buf.Write(h)
			nNodes++
		}

		nNodes >>= 1
		level++

		for i := uint64(0); i < nNodes; i++ {
			leftRight := buf.Bytes()[offset+2*HashLen*int(i):]
			left := leftRight[:HashLen]
			right := leftRight[HashLen : 2*HashLen]
			if err := batch.hashNode(h, left, right, i, level); err != nil {
				return nil, err
			}
			_, _ = buf.Write(h)
		}

		offset += 2 * int(nNodes*HashLen)
	}

	return &Tree{buf: buf.Bytes(), nLeaves: nLeaves}, nil
}

// Computes the leaf hash of the assertion.
func (a *AbridgedAssertion) Hash(out []byte, batch *Batch, index uint64) error {
	var b cryptobyte.Builder
	b.AddUint8(2)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(batch.CA.IssuerId))
	})
	b.AddUint32(batch.Number)
	b.AddUint64(index)
	buf, err := a.MarshalBinary()
	if err != nil {
		return err
	}
	b.AddBytes(buf)
	buf, err = b.Bytes()
	if err != nil {
		return err
	}
	h := sha256.New()
	_, _ = h.Write(buf)
	h.Sum(out[:0])
	return nil
}

var domainLabelRegex = regexp.MustCompile("^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$")

func (c Claims) String() string {
	bits := []string{}
	if len(c.DNS) != 0 {
		bits = append(bits, c.DNS...)
	}
	if len(c.DNSWildcard) != 0 {
		for _, domain := range c.DNSWildcard {
			bits = append(bits, "*."+domain)
		}
	}
	if len(c.IPv4) != 0 {
		for _, ip := range c.IPv4 {
			bits = append(bits, ip.String())
		}
	}
	if len(c.IPv6) != 0 {
		for _, ip := range c.IPv6 {
			bits = append(bits, ip.String())
		}
	}
	if len(c.Unknown) != 0 {
		for _, claim := range c.Unknown {
			bits = append(bits, fmt.Sprintf(
				"<unknown claim of type %d>",
				uint16(claim.Type),
			))
		}
	}
	return strings.Join(bits, ", ")
}

// Checks whether the given strings are valid domain names, and sorts them
// hierarchically.
func sortAndCheckDomainNames(ds []string) ([]string, error) {
	splitDomains := make([][]string, 0, len(ds))

	for _, domain := range ds {
		if len(domain) == 0 {
			return nil, errors.New("Empty domain name")
		}
		if len(domain) >= 256 {
			return nil, errors.New("Domain name too long")
		}
		splitDomain := strings.Split(domain, ".")
		for _, label := range splitDomain {
			if len(label) >= 64 {
				return nil, errors.New("Label in domain name too long")
			}
			if !domainLabelRegex.Match([]byte(label)) {
				return nil, errors.New(
					"Label in domain contains invalid characters")
			}
		}
		splitDomains = append(splitDomains, splitDomain)
	}
	sort.Slice(splitDomains, func(i, j int) bool {
		for k := 0; ; k++ {
			if len(splitDomains[j]) == k {
				return false
			}
			if len(splitDomains[i]) == k {
				return true
			}
			a := splitDomains[i][len(splitDomains[i])-k-1]
			b := splitDomains[j][len(splitDomains[j])-k-1]
			if a == b {
				continue
			}
			return a < b
		}
	})

	ret := make([]string, 0, len(ds))
	for _, splitDomain := range splitDomains {
		ret = append(ret, strings.Join(splitDomain, "."))
	}

	return ret, nil
}

func (c *Claims) UnmarshalBinary(data []byte) error {
	*c = Claims{}

	s := cryptobyte.String(data)

	var previousType ClaimType
	first := true

	for !s.Empty() {
		var (
			claimInfo cryptobyte.String
			claimType ClaimType
		)

		if !s.ReadUint16((*uint16)(&claimType)) ||
			!s.ReadUint16LengthPrefixed(&claimInfo) {
			return ErrTruncated
		}

		if first {
			first = false
		} else {
			if previousType >= claimType {
				return errors.New("Claims duplicated or not sorted")
			}
			previousType = claimType
		}

		switch claimType {
		case DnsClaimType, DnsWildcardClaimType:
			var (
				packed  cryptobyte.String
				domains []string
			)

			if !claimInfo.ReadUint16LengthPrefixed(&packed) {
				return ErrTruncated
			}

			if !claimInfo.Empty() {
				return ErrExtraBytes
			}

			if packed.Empty() {
				return errors.New("Domain claim must list at least one domain")
			}

			for !packed.Empty() {
				var domain []byte
				if !packed.ReadUint16LengthPrefixed((*cryptobyte.String)(&domain)) {
					return ErrTruncated
				}

				domains = append(domains, string(domain))
			}

			sorted, err := sortAndCheckDomainNames(domains)
			if err != nil {
				return err
			}
			if !slices.Equal(sorted, domains) {
				return errors.New("Domains were not sorted")
			}

			if claimType == DnsClaimType {
				c.DNS = domains
			} else {
				c.DNSWildcard = domains
			}

		case Ipv4ClaimType, Ipv6ClaimType:
			var (
				packed cryptobyte.String
				ips    []net.IP
			)

			if !claimInfo.ReadUint16LengthPrefixed(&packed) {
				return ErrTruncated
			}

			if !claimInfo.Empty() {
				return ErrExtraBytes
			}

			entrySize := 16
			if claimType == Ipv4ClaimType {
				entrySize = 4
			}

			if packed.Empty() {
				return errors.New("IP claim must list at leats one IP")
			}

			first := true
			var previousIp net.IP
			for !packed.Empty() {
				var ip net.IP
				if !packed.ReadBytes((*[]byte)(&ip), entrySize) {
					return ErrTruncated
				}
				if first {
					first = false
				} else {
					if slices.Compare(previousIp, ip) >= 0 {
						return errors.New("IPs were not sorted")
					}
					previousIp = ip
				}

				ips = append(ips, ip)
			}

			if claimType == Ipv4ClaimType {
				c.IPv4 = ips
			} else {
				c.IPv6 = ips
			}

		default:
			c.Unknown = append(
				c.Unknown,
				UnknownClaim{
					Type: claimType,
					Info: []byte(claimInfo),
				},
			)
		}
	}

	return nil
}

func (c *Claims) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder

	marshalDomains := func(domains []string, claimType ClaimType) error {
		if len(domains) == 0 {
			return nil
		}
		sorted, err := sortAndCheckDomainNames(domains)
		if err != nil {
			return err
		}

		b.AddUint16(uint16(claimType))
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // claim_info
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // dns_names
				for _, domain := range sorted {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(domain))
					})
				}
			})
		})
		return nil
	}

	if err := marshalDomains(c.DNS, DnsClaimType); err != nil {
		return nil, err
	}
	if err := marshalDomains(c.DNSWildcard, DnsWildcardClaimType); err != nil {
		return nil, err
	}

	marshalIPs := func(ips []net.IP, ipv4 bool) error {
		if len(ips) == 0 {
			return nil
		}

		sorted := make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			if ipv4 {
				ip = ip.To4()
			} else {
				ip = ip.To16()
			}
			if ip == nil {
				return errors.New("Not a valid IP address")
			}
			sorted = append(sorted, ip)
		}
		sort.Slice(sorted, func(i, j int) bool {
			return slices.Compare(sorted[i], sorted[j]) < 0
		})

		if ipv4 {
			b.AddUint16(uint16(Ipv4ClaimType))
		} else {
			b.AddUint16(uint16(Ipv6ClaimType))
		}
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // claim_info
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // addresses
				for _, ip := range sorted {
					b.AddBytes([]byte(ip))
				}
			})
		})
		return nil
	}

	if err := marshalIPs(c.IPv4, true); err != nil {
		return nil, err
	}
	if err := marshalIPs(c.IPv6, false); err != nil {
		return nil, err
	}

	for i := 0; i < len(c.Unknown); i++ {
		claim := c.Unknown[i]
		if i == 0 {
			if claim.Type <= Ipv6ClaimType {
				return nil, errors.New("Parseable UnknownClaim")
			}
		} else {
			if claim.Type <= c.Unknown[i-1].Type {
				return nil, errors.New("Duplicate or unsorted unknown claims")
			}
		}

		b.AddUint16(uint16(claim.Type))
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(claim.Info)
		})
	}

	return b.Bytes()
}
