package mtc

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// CAParams holds the public parameters of a Merkle Tree CA
type CAParams struct {
	Issuer        RelativeOID
	PublicKey     Verifier
	ProofType     ProofType
	StartTime     uint64
	BatchDuration uint64
	Lifetime      uint64

	// ValidityWindowSize is the number of tree heads in each validity
	// window.
	ValidityWindowSize uint64

	StorageWindowSize uint64
	ServerPrefix      string
	EvidencePolicy    EvidencePolicyType
}

const (
	HashLen = 32

	// Version of the API we implement. It's close to draft -04, but there
	// are changes on top, hence the "b".
	ApiVersion = "v04b"
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

type EvidenceType uint16

const (
	UmbilicalEvidenceType EvidenceType = iota
	CompressedUmbilicalEvidenceType
)

type EvidenceList []Evidence

type Evidence interface {
	Type() EvidenceType
	Info() []byte
}

type UmbilicalEvidence []byte
type CompressedUmbilicalEvidence [][32]byte

type UnknownEvidence struct {
	typ  EvidenceType
	info []byte
}

type EvidencePolicyType uint16

const (
	// No policy set.
	UnsetEvidencePolicy EvidencePolicyType = iota

	// Policy requiring no evidence to queue an assertion request.
	EmptyEvidencePolicy

	// Policy requiring an X509 chain to an accepted root to queue an assertion request.
	UmbilicalEvidencePolicy
)

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

type BatchEntry struct {
	Subject  AbridgedSubject
	Claims   Claims
	NotAfter time.Time
}

type AssertionRequest struct {
	Checksum  []byte
	Assertion Assertion
	Evidence  EvidenceList
	NotAfter  time.Time
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

	// Just for testing we use ML-DSA-87 with a codepoint in the
	// private use region.
	// For production SLH-DSA-128s would be a better choice.
	TLSMLDSA87 SignatureScheme = 0x0906
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

type Proof interface {
	TrustAnchorIdentifier() TrustAnchorIdentifier
	Info() []byte
	NotAfter() time.Time
}

type MerkleTreeProof struct {
	anchor   TrustAnchorIdentifier
	notAfter time.Time
	index    uint64
	path     []byte
}

type UnknownProof struct {
	anchor   TrustAnchorIdentifier
	notAfter time.Time
	info     []byte
}

type ValidityWindow struct {
	// BatchNumber is the batch number of the last tree head.
	BatchNumber uint32
	TreeHeads   []byte
}

type SignedValidityWindow struct {
	ValidityWindow
	Signature []byte
}

func (p *MerkleTreeProof) NotAfter() time.Time {
	return p.notAfter
}

func (p *MerkleTreeProof) TrustAnchorIdentifier() TrustAnchorIdentifier {
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

func (p *MerkleTreeProof) Path() []byte {
	return p.path
}

func (p *MerkleTreeProof) Index() uint64 {
	return p.index
}

func (p *UnknownProof) TrustAnchorIdentifier() TrustAnchorIdentifier {
	return p.anchor
}

func (p *UnknownProof) NotAfter() time.Time {
	return p.notAfter
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
	if r.End == r.Begin+1 {
		return fmt.Sprintf("%d", r.Begin)
	}
	if r.End == r.Begin+2 {
		return fmt.Sprintf("%d,%d", r.Begin, r.Begin+1)
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
func (t *Tree) WriteTo(w io.Writer) (int64, error) {
	var b cryptobyte.Builder
	b.AddUint64(t.nLeaves)
	buf, err := b.Bytes()
	if err != nil {
		return 0, err
	}
	n1, err := w.Write(buf)
	if err != nil {
		return int64(n1), err
	}
	n2, err := w.Write(t.buf)
	return int64(n1 + n2), err
}

func (t *Tree) NodeCount() uint {
	return TreeNodeCount(t.nLeaves)
}

// TreeNodeCount returns the number of nodes in the Merkle tree for a batch, which has
// nLeaves assertions.
func TreeNodeCount(nLeaves uint64) uint {
	if nLeaves == 0 {
		return 1
	}

	nodesInLayer := uint(nLeaves)
	ret := uint(0)
	for nodesInLayer != 1 {
		if nodesInLayer&1 == 1 {
			nodesInLayer++
		}

		ret += nodesInLayer
		nodesInLayer >>= 1
	}
	ret++ // we didn't count the root yet
	return ret
}

func (t *Tree) UnmarshalBinary(buf []byte) error {
	s := cryptobyte.String(buf)
	if !s.ReadUint64(&t.nLeaves) {
		return ErrTruncated
	}

	nNodes := TreeNodeCount(t.nLeaves)

	t.buf = make([]byte, int(nNodes)*HashLen)
	if !s.CopyBytes(t.buf) {
		return ErrTruncated
	}
	if !s.Empty() {
		return ErrExtraBytes
	}
	return nil
}

func (c *BikeshedCertificate) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	buf, err := c.Assertion.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Assertion: %w", err)
	}
	b.AddBytes(buf)

	buf, err = c.Proof.TrustAnchorIdentifier().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TAI: %w", err)
	}
	b.AddBytes(buf)

	notAfter := c.Proof.NotAfter().Unix()
	if notAfter < 0 {
		return nil, errors.New("negative timestamp")
	}
	b.AddUint64(uint64(notAfter))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(c.Proof.Info())
	})
	return b.Bytes()
}

func (c *BikeshedCertificate) UnmarshalBinary(data []byte, caStore CAStore) error {
	s := cryptobyte.String(data)
	err := c.Assertion.unmarshal(&s)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Assertion: %w", err)
	}
	var (
		proofInfo cryptobyte.String
	)
	tai := TrustAnchorIdentifier{}
	err = tai.unmarshal(&s)
	if err != nil {
		return fmt.Errorf("failed to unmarshal TrustAnchorIdentifier: %w", err)
	}
	var notAfter uint64
	if !s.ReadUint64(&notAfter) || !s.ReadUint16LengthPrefixed(&proofInfo) {
		return ErrTruncated
	}
	if !s.Empty() {
		return ErrExtraBytes
	}
	if notAfter >= 1<<63 {
		return errors.New("timestamp too large")
	}
	switch tai.ProofType(caStore) {
	case MerkleTreeProofType:
		proof := &MerkleTreeProof{
			notAfter: time.Unix(int64(notAfter), 0),
		}
		if !proofInfo.ReadUint64(&proof.index) ||
			!copyUint16LengthPrefixed(&proofInfo, &proof.path) {
			return ErrTruncated
		}
		if !proofInfo.Empty() {
			return ErrExtraBytes
		}
		proof.anchor = tai
		c.Proof = proof
		return nil
	}
	c.Proof = &UnknownProof{
		notAfter: time.Unix(int64(notAfter), 0),
		anchor:   tai,
		info:     []byte(proofInfo),
	}
	return nil
}

// VerifyOptions includes parameters for verifying a BikeshedCertificate.
type VerifyOptions struct {
	// ValidityWindow is a validity window that covers the certificate. It
	// is the caller's responsibility to verify the validity window was
	// signed by the CA, e.g., by verifying the SignedValidityWindow that
	// contains the validity window.
	ValidityWindow *ValidityWindow

	// CA includes the parameters of the CA that issued the batch
	// containing the certificate.
	CA *CAParams

	// CurrentTime is used to to check if the certificate has expired.
	CurrentTime time.Time
}

// Verify is used to verify that a BikeshedCertificate is covered by a validity
// window. It is the caller's responsibility to verify the validity window was
// signed by the CA. An error indicates that the certificate does not belong to
// a batch in the validity window or that the certificate is otherwise invalid.
func (c *BikeshedCertificate) Verify(opts VerifyOptions) error {
	if opts.ValidityWindow == nil {
		return errors.New("Missing validity window")
	}

	if opts.CA == nil {
		return errors.New("Missing CA parameters")
	}

	p, ok := c.Proof.(*MerkleTreeProof)
	if !ok {
		return fmt.Errorf("Expected MerkleTreeProof; got %t", c.Proof)
	}
	certBatchNumber := p.TrustAnchorIdentifier().BatchNumber

	b := Batch{
		CA:     opts.CA,
		Number: certBatchNumber,
	}

	// If the current time wasn't set, then use use time.Now().
	currentTime := opts.CurrentTime
	if currentTime.IsZero() {
		currentTime = time.Now()
	}

	// Check if the certificate is not yet valid.
	notBefore, _ := b.ValidityInterval()
	if currentTime.Before(notBefore) {
		return fmt.Errorf("Certificate is not yet valid (%v)", p.NotAfter().UTC())
	}

	// Check if the certificate has expired.
	if currentTime.After(c.Proof.NotAfter()) {
		return fmt.Errorf("Certificate has expired (%v)", p.NotAfter().UTC())
	}

	// Check that the certificate issuer matches the CA.
	if !bytes.Equal(p.TrustAnchorIdentifier().Issuer, opts.CA.Issuer) {
		return fmt.Errorf("Certificate issuer (%s) does not match CA (%s)",
			p.TrustAnchorIdentifier().Issuer, opts.CA.Issuer)
	}

	// Select the tree head.
	head, err := opts.ValidityWindow.headForBatch(certBatchNumber, opts.CA)
	if err != nil {
		return err
	}

	// Verify the authentication path.
	be := NewBatchEntry(c.Assertion, p.NotAfter())
	err = b.VerifyAuthenticationPath(p.Index(), p.Path(), head, &be)
	if err != nil {
		return err
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
		End:   uint32(currentNumber) + 1,
	}
}

// Returns the time when the next batch starts.
func (p *CAParams) NextBatchAt(dt time.Time) time.Time {
	ts := dt.Unix()
	currentNumber := (ts - int64(p.StartTime)) / int64(p.BatchDuration)
	if currentNumber < 0 {
		return time.Unix(int64(p.StartTime), 0)
	}

	return time.Unix(
		int64(p.StartTime+p.BatchDuration*uint64(currentNumber+1)),
		0,
	)
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
		End:   uint32(currentNumber) + 1,
	}
}

func (p *CAParams) MarshalBinary() ([]byte, error) {
	// TODO add struct to I-D
	var b cryptobyte.Builder
	var issuer, err = p.Issuer.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.AddBytes(issuer)
	b.AddUint16(uint16(p.PublicKey.Scheme()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(p.PublicKey.Bytes())
	})
	b.AddUint16(uint16(p.ProofType))
	b.AddUint64(p.StartTime)
	b.AddUint64(p.BatchDuration)
	b.AddUint64(p.Lifetime)
	b.AddUint64(p.ValidityWindowSize)
	b.AddUint64(p.StorageWindowSize)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(p.ServerPrefix))
	})
	b.AddUint16(uint16(p.EvidencePolicy))
	return b.Bytes()
}

func (p *CAParams) UnmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)
	var (
		issuerBuf       []byte
		pkBuf           []byte
		serverPrefixBuf []byte
		sigScheme       SignatureScheme
		err             error
	)

	if !s.ReadUint8LengthPrefixed((*cryptobyte.String)(&issuerBuf)) ||
		!s.ReadUint16((*uint16)(&sigScheme)) ||
		!s.ReadUint16LengthPrefixed((*cryptobyte.String)(&pkBuf)) ||
		!s.ReadUint16((*uint16)(&p.ProofType)) ||
		!s.ReadUint64(&p.StartTime) ||
		!s.ReadUint64(&p.BatchDuration) ||
		!s.ReadUint64(&p.Lifetime) ||
		!s.ReadUint64(&p.ValidityWindowSize) ||
		!s.ReadUint64(&p.StorageWindowSize) ||
		!s.ReadUint16LengthPrefixed((*cryptobyte.String)(&serverPrefixBuf)) ||
		!s.ReadUint16((*uint16)(&p.EvidencePolicy)) {
		return ErrTruncated
	}

	if !s.Empty() {
		return ErrExtraBytes
	}

	p.Issuer = issuerBuf
	p.ServerPrefix = string(serverPrefixBuf)
	p.PublicKey, err = UnmarshalVerifier(sigScheme, pkBuf)
	if err != nil {
		return err
	}

	return p.Validate()
}

func (p *CAParams) Validate() error {
	// If the issuer uses the full 255 bytes, there can be at most 128 batches,
	// as there is only a single byte left for encoding the batch.
	// TODO Maybe reduce the maximum allowed size of the issuer OID.
	if len(p.Issuer) > 255 {
		return errors.New("issuer must be 255 bytes or less")
	}
	if len(p.Issuer) == 0 {
		return errors.New("issuer can't be empty")
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

// Returns the tree heads of the validity window prior the epoch.
func (p *CAParams) PreEpochTreeHeads() []byte {
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
	w.TreeHeads = make([]byte, int(HashLen*p.ValidityWindowSize))
	if !s.ReadUint32(&w.BatchNumber) || !s.CopyBytes(w.TreeHeads) {
		return ErrTruncated
	}

	return nil
}

func (w *SignedValidityWindow) UnmarshalBinary(data []byte, p *CAParams) error {
	err := w.UnmarshalBinaryWithoutVerification(data, p)
	if err != nil {
		return err
	}
	toSign, err := w.ValidityWindow.LabeledValdityWindow(p)
	if err != nil {
		return err
	}
	return p.PublicKey.Verify(toSign, w.Signature)
}

// Like UnmarshalBinary() but doesn't check the signature.
func (w *SignedValidityWindow) UnmarshalBinaryWithoutVerification(
	data []byte, p *CAParams) error {
	s := cryptobyte.String(data)
	err := w.ValidityWindow.unmarshal(&s, p)
	if err != nil {
		return err
	}
	if !copyUint16LengthPrefixed(&s, &w.Signature) {
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

// Return the tree head recorded for this ValidityWindow's batch.
func (w *ValidityWindow) CurHead() []byte {
	return w.TreeHeads[:HashLen]
}

func (w *ValidityWindow) headForBatch(number uint32, p *CAParams) ([]byte,
	error) {
	maxBatchNumber := w.BatchNumber
	minBatchNumber := uint32(0)
	if max := uint64(maxBatchNumber); max > p.ValidityWindowSize {
		minBatchNumber = uint32(max - p.ValidityWindowSize)
	}
	if number < minBatchNumber || number > maxBatchNumber {
		return nil, fmt.Errorf("Batch number (%d) out of range [%d, %d]",
			number, minBatchNumber, maxBatchNumber)
	}

	headIndex := int(HashLen * (maxBatchNumber - number))
	head := w.TreeHeads[headIndex : headIndex+HashLen]
	return head, nil
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

	var issuer, err = ca.Issuer.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.AddBytes(issuer)
	buf, err := w.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.AddBytes(buf)
	return b.Bytes()
}

// Returns TreeHeads from the previous batch's TreeHeads and the new root.
func (p *CAParams) NewTreeHeads(prevHeads, root []byte) ([]byte, error) {
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
	return append(root, prevHeads[HashLen:]...), nil
}

func (batch *Batch) Anchor() TrustAnchorIdentifier {
	tai := TrustAnchorIdentifier{
		Issuer:      batch.CA.Issuer,
		BatchNumber: batch.Number,
	}
	return tai
}

func (batch *Batch) SignValidityWindow(signer Signer, prevHeads []byte,
	root []byte) (SignedValidityWindow, error) {
	newHeads, err := batch.CA.NewTreeHeads(prevHeads, root)
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

// ValidityInterval returns the largest closed interval [a,b] in which
// assertions issued in this batch are valid. That is: for all times x with a ≤
// x ≤ b. Note that NotAfter may be smaller than b for some assertions.
func (batch *Batch) ValidityInterval() (time.Time, time.Time) {
	start := batch.CA.StartTime + uint64(batch.Number)*batch.CA.BatchDuration
	end := start + batch.CA.Lifetime - 1
	return time.Unix(int64(start), 0), time.Unix(int64(end), 999999999)
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

func (p ProofType) String() string {
	switch p {
	case MerkleTreeProofType:
		return "merkle_tree_sha256"
	default:
		return fmt.Sprintf("ProofType(%d)", p)
	}
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

func NewBatchEntry(a Assertion, notAfter time.Time) (ret BatchEntry) {
	ret.Claims = a.Claims
	ret.Subject = a.Subject.Abridge()
	ret.NotAfter = notAfter
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
		subjectInfo []byte
		claims      cryptobyte.String
	)
	if !s.ReadUint16((*uint16)(&subjectType)) ||
		!copyUint16LengthPrefixed(s, &subjectInfo) ||
		!s.ReadUint16LengthPrefixed(&claims) {
		return ErrTruncated
	}

	if err := a.Claims.UnmarshalBinary([]byte(claims)); err != nil {
		return fmt.Errorf("Failed to unmarshal claims: %w", err)
	}

	switch subjectType {
	case TLSSubjectType:
		a.Subject = &TLSSubject{
			packed: subjectInfo,
		}
	default:
		a.Subject = &UnknownSubject{
			typ:  subjectType,
			info: subjectInfo,
		}
	}

	return nil
}

func (be *BatchEntry) maxSize() int {
	return (65535+2)*2 + 2 + 8
}

func (be *BatchEntry) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(uint16(be.Subject.Type()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // abridged_subject_info
		b.AddBytes(be.Subject.Info())
	})
	claims, err := be.Claims.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(claims)
	})
	notAfter := be.NotAfter.Unix()
	if notAfter < 0 {
		return nil, errors.New("negative timestamp")
	}
	b.AddUint64(uint64(notAfter))
	return b.Bytes()
}

func (be *BatchEntry) UnmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)
	err := be.unmarshal(&s)
	if err != nil {
		return err
	}
	if !s.Empty() {
		return ErrExtraBytes
	}
	return nil
}

func (be *BatchEntry) unmarshal(s *cryptobyte.String) error {
	var (
		subjectType SubjectType
		subjectInfo cryptobyte.String
		claims      cryptobyte.String
		notAfter    uint64
	)
	if !s.ReadUint16((*uint16)(&subjectType)) ||
		!s.ReadUint16LengthPrefixed(&subjectInfo) ||
		!s.ReadUint16LengthPrefixed(&claims) ||
		!s.ReadUint64(&notAfter) {
		return ErrTruncated
	}

	if err := be.Claims.UnmarshalBinary([]byte(claims)); err != nil {
		return fmt.Errorf("Failed to unmarshal claims: %w", err)
	}

	if notAfter >= 1<<63 {
		return errors.New("timestamp too large")
	}
	be.NotAfter = time.Unix(int64(notAfter), 0)

	switch subjectType {
	case TLSSubjectType:
		var subject AbridgedTLSSubject
		if !subjectInfo.ReadUint16((*uint16)(&subject.SignatureScheme)) ||
			!subjectInfo.CopyBytes(subject.PublicKeyHash[:]) {
			return ErrTruncated
		}
		if !subjectInfo.Empty() {
			return ErrExtraBytes
		}
		be.Subject = &subject
	default:
		subjectInfoBuf := make([]byte, len(subjectInfo))
		copy(subjectInfoBuf, subjectInfo)
		be.Subject = &UnknownSubject{
			typ:  subjectType,
			info: subjectInfoBuf,
		}
	}

	return nil
}

func (e CompressedUmbilicalEvidence) Type() EvidenceType {
	return CompressedUmbilicalEvidenceType
}
func (e CompressedUmbilicalEvidence) Info() []byte {
	ret := make([]byte, len(e)*32)
	for i, key := range e {
		copy(ret[32*i:], key[:])
	}
	return ret
}
func (e CompressedUmbilicalEvidence) Chain() [][32]byte {
	return e
}
func (e *CompressedUmbilicalEvidence) UnmarshalBinary(buf []byte) error {
	if len(buf)&31 != 0 {
		return errors.New("CompressedUmbilicalEvidence must be multiple of 32 bytes")
	}
	*e = make([][32]byte, len(buf)>>5)
	for i := range len(buf) >> 5 {
		copy((*e)[i][:], buf[32*i:32*(i+1)])
	}
	return nil
}
func NewCompressedUmbilicalEvidence(certs [][32]byte) (
	CompressedUmbilicalEvidence, error) {
	return certs, nil
}

func (e UmbilicalEvidence) Type() EvidenceType { return UmbilicalEvidenceType }
func (e UmbilicalEvidence) Info() []byte       { return e }
func (e UmbilicalEvidence) Chain() ([]*x509.Certificate, error) {
	return x509.ParseCertificates(e)
}
func (e UmbilicalEvidence) RawChain() ([][]byte, error) {
	// Instead of completely parsing the certificates, we'll read the
	// outer SEQUENCE tag to figure out the boundaries.
	s := cryptobyte.String(e)
	offset := 0
	prev := len(s)
	var ret [][]byte
	for !s.Empty() {
		if !s.SkipASN1(asn1.SEQUENCE) {
			return nil, errors.New("UmbilicalEvidence: unexpected ASN.1 tag")
		}
		length := prev - len(s)
		prev = len(s)
		ret = append(ret, e[offset:offset+length])
		offset += length
	}
	return ret, nil
}
func NewUmbilicalEvidence(certs []*x509.Certificate) (UmbilicalEvidence, error) {
	var b cryptobyte.Builder
	for _, cert := range certs {
		b.AddBytes(cert.Raw)
	}
	return b.Bytes()
}

func (e UnknownEvidence) Type() EvidenceType { return e.typ }
func (e UnknownEvidence) Info() []byte       { return e.info }

func (ar *AssertionRequest) UnmarshalBinary(data []byte) error {
	var (
		notAfter uint64
		s        cryptobyte.String = cryptobyte.String(data)
	)
	ar.Checksum = make([]byte, sha256.Size)
	if !s.CopyBytes(ar.Checksum) {
		return ErrTruncated
	}

	err := ar.Assertion.unmarshal(&s)
	if err != nil {
		return err
	}

	err = ar.Evidence.unmarshal(&s)
	if err != nil {
		return err
	}

	if !s.ReadUint64(&notAfter) {
		return ErrTruncated
	}
	ar.NotAfter = time.Unix(int64(notAfter), 0)

	if !s.Empty() {
		return ErrExtraBytes
	}

	err = ar.Check()
	if err != nil {
		return err
	}

	return nil
}

func (ar *AssertionRequest) marshalAndCheckAssertionRequest() ([]byte, error) {
	var b cryptobyte.Builder

	buf, err := ar.Assertion.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.AddBytes(buf)

	buf, err = ar.Evidence.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.AddBytes(buf)

	b.AddUint64(uint64(ar.NotAfter.Unix()))

	checksumBytes, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	checksum2 := sha256.Sum256(checksumBytes)
	if ar.Checksum == nil {
		ar.Checksum = checksum2[:]
	} else if !bytes.Equal(checksum2[:], ar.Checksum) {
		return nil, ErrChecksumInvalid
	}

	return b.Bytes()
}

// If set, checks whether the Checksum is correct. If not set, sets the
// Checksum to the correct value.
func (ar *AssertionRequest) Check() error {
	_, err := ar.marshalAndCheckAssertionRequest()
	return err
}

func (ar *AssertionRequest) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder

	buf, err := ar.marshalAndCheckAssertionRequest()
	if err != nil {
		return nil, err
	}
	b.AddBytes(ar.Checksum)
	b.AddBytes(buf)

	return b.Bytes()
}

func (t *Tree) LeafCount() uint64 {
	return t.nLeaves
}

// Return head (root) of the tree
func (t *Tree) Head() []byte {
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

// Unmarshals BatchEntry from r.
func UnmarshalBatchEntries(r io.Reader) Cursor[*BatchEntry] {
	return unmarshal[*BatchEntry](r)
}

// Unmarshals BatchEntry from r, keeping note of the offset of each.
func UnmarshalBatchEntriesWithOffset(r io.Reader) Cursor[*BatchEntryWithOffset] {
	return unmarshal[*BatchEntryWithOffset](r)
}

// Unmarshals a single BatchEntry from r.
func UnmarshalBatchEntry(r io.Reader) (*BatchEntry, error) {
	return unmarshalOne[*BatchEntry](r)
}

// Compute batch tree head from authentication path.
//
// To verify a certificate/proof, use VerifyAuthenticationPath instead.
func (batch *Batch) ComputeTreeHeadFromAuthenticationPath(index uint64,
	path []byte, be *BatchEntry) ([]byte, error) {
	h := make([]byte, HashLen)
	if err := be.Hash(h[:], batch, index); err != nil {
		return nil, err
	}

	level := uint8(0)
	var left, right []byte
	for len(path) != 0 {
		if len(path) < HashLen {
			return nil, ErrTruncated
		}

		left, right, path = h, path[:HashLen], path[HashLen:]
		if index&1 == 1 {
			left, right = right, left
		}

		level++
		index >>= 1

		_ = batch.hashNode(h, left, right, index, level)
	}

	if index != 0 {
		return nil, fmt.Errorf("Authentication path too short")
	}

	return h, nil
}

// Check validity of authentication path.
//
// Return nil on valid authentication path.
func (batch *Batch) VerifyAuthenticationPath(index uint64, path, root []byte,
	be *BatchEntry) error {

	h, err := batch.ComputeTreeHeadFromAuthenticationPath(index, path, be)
	if err != nil {
		return err
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
	tai, err := TrustAnchorIdentifier{
		Issuer:      batch.CA.Issuer,
		BatchNumber: batch.Number,
	}.MarshalBinary()
	if err != nil {
		return err
	}
	b.AddBytes(tai)
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
	tai, err := TrustAnchorIdentifier{
		Issuer:      batch.CA.Issuer,
		BatchNumber: batch.Number,
	}.MarshalBinary()
	if err != nil {
		return err
	}
	b.AddBytes(tai)
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

type TreeBuilder struct {
	leafHashes *bytes.Buffer
	index      uint64
	batch      *Batch
	err        error
}

func (batch *Batch) NewTreeBuilder() *TreeBuilder {
	return &TreeBuilder{
		leafHashes: &bytes.Buffer{},
		batch:      batch,
	}
}

func (b *TreeBuilder) Push(be *BatchEntry) error {
	var hash [HashLen]byte

	if b.err != nil {
		return b.err
	}

	if err := be.Hash(hash[:], b.batch, b.index); err != nil {
		b.err = err
		return err
	}

	_, _ = b.leafHashes.Write(hash[:])
	b.index++

	return nil
}

func (b *TreeBuilder) Finish() (*Tree, error) {
	if b.err != nil {
		return nil, b.err
	}

	leaves := b.leafHashes.Bytes()
	nLeaves := uint64(len(leaves)) / uint64(HashLen)
	buf := bytes.NewBuffer(leaves)

	if nLeaves == 0 {
		tree := &Tree{
			nLeaves: 0,
			buf:     make([]byte, HashLen),
		}
		if err := b.batch.hashEmpty(tree.buf[:], 0, 0); err != nil {
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
			if err := b.batch.hashEmpty(h, nNodes, level); err != nil {
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
			if err := b.batch.hashNode(h, left, right, i, level); err != nil {
				return nil, err
			}
			_, _ = buf.Write(h)
		}

		offset += 2 * int(nNodes*HashLen)
	}

	return &Tree{buf: buf.Bytes(), nLeaves: nLeaves}, nil
}

// Convenience function to compute Merkle tree from
// a stream of BatchEntry from r.
func (batch *Batch) ComputeTree(r io.Reader) (*Tree, error) {
	tb := batch.NewTreeBuilder()
	err := ForEach(
		UnmarshalBatchEntries(r),
		tb.Push,
	)
	if err != nil {
		return nil, err
	}
	return tb.Finish()
}

// Computes the key a BatchEntry for this assertion would have in the index.
func (a *Assertion) EntryKey(out []byte) error {
	// We use dummy not_after, as it's ignored in the key.
	be := NewBatchEntry(*a, time.Unix(0, 0))
	return be.Key(out)
}

// Computes the key of the BatchEntry used in the index.
//
// Note that keys are not unique: we leave out the not_after field when
// computing the key. This allows us to look up a BatchEntry for some
// assertion that does not contain the not_after field.
func (be *BatchEntry) Key(out []byte) error {
	if len(out) != 32 {
		return errors.New("BatchEntry keys are 32 bytes")
	}
	buf, err := be.MarshalBinary()
	if err != nil {
		return err
	}
	h := sha256.New()
	_, _ = h.Write(buf[:len(buf)-8]) // skip not_after at the end
	h.Sum(out[:0])
	return nil
}

// Computes the leaf hash of the BatchEntry in the Merkle tree
// computed for the batch.
func (be *BatchEntry) Hash(out []byte, batch *Batch, index uint64) error {
	var b cryptobyte.Builder
	b.AddUint8(2)
	tai, err := TrustAnchorIdentifier{
		Issuer:      batch.CA.Issuer,
		BatchNumber: batch.Number,
	}.MarshalBinary()
	if err != nil {
		return err
	}
	b.AddBytes(tai)
	b.AddUint64(index)
	buf, err := be.MarshalBinary()
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
				if !packed.ReadUint8LengthPrefixed((*cryptobyte.String)(&domain)) {
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
				var ip net.IP = net.IP(make([]byte, entrySize))
				if !packed.CopyBytes([]byte(ip)) {
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
			clm := UnknownClaim{
				Type: claimType,
				Info: make([]byte, len(claimInfo)),
			}
			copy(clm.Info, claimInfo)
			c.Unknown = append(
				c.Unknown,
				clm,
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
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
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

	for i := range len(c.Unknown) {
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

func (el *EvidenceList) UnmarshalBinary(data []byte) error {
	*el = EvidenceList{}
	s := cryptobyte.String(data)
	err := el.unmarshal(&s)
	if err != nil {
		return err
	}
	if !s.Empty() {
		return ErrExtraBytes
	}
	return nil
}

func (el *EvidenceList) unmarshal(s *cryptobyte.String) error {

	var (
		evidenceList cryptobyte.String
		evidenceInfo cryptobyte.String
		evidenceType EvidenceType
	)

	if !s.ReadUint24LengthPrefixed(&evidenceList) {
		return ErrTruncated
	}

	*el = nil

	for !evidenceList.Empty() {
		if !evidenceList.ReadUint16((*uint16)(&evidenceType)) ||
			!evidenceList.ReadUint24LengthPrefixed(&evidenceInfo) {
			return ErrTruncated
		}

		switch evidenceType {
		case CompressedUmbilicalEvidenceType:
			var e CompressedUmbilicalEvidence
			if err := e.UnmarshalBinary(evidenceInfo); err != nil {
				return err
			}
			*el = append(*el, e)
		case UmbilicalEvidenceType:
			*el = append(*el, UmbilicalEvidence(evidenceInfo))
		default:
			*el = append(*el, UnknownEvidence{
				typ:  evidenceType,
				info: evidenceInfo,
			})
		}
	}

	return nil
}

func (el *EvidenceList) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder

	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, e := range *el {
			b.AddUint16(uint16(e.Type()))
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(e.Info())
			})
		}
	})

	return b.Bytes()
}

// Unmarshals EvidenceLists from r.
func UnmarshalEvidenceLists(r io.Reader) Cursor[*EvidenceList] {
	return unmarshal[*EvidenceList](r)
}

// Unmarshals single EvidenceList from r.
func UnmarshalEvidenceList(r io.Reader) (*EvidenceList, error) {
	return unmarshalOne[*EvidenceList](r)
}

func (el *EvidenceList) maxSize() int {
	return (65535+2)*2 + 2
}

func NewMerkleTreeProof(batch *Batch, index uint64, notAfter time.Time,
	path []byte) *MerkleTreeProof {
	return &MerkleTreeProof{
		anchor:   batch.Anchor(),
		index:    index,
		path:     path,
		notAfter: notAfter,
	}
}

type CAStore interface {
	Lookup(oid RelativeOID) CAParams
}

type LocalCAStore struct {
	store map[string]CAParams
}

func (s *LocalCAStore) Lookup(oid RelativeOID) CAParams {
	return s.store[oid.String()]
}

func (s *LocalCAStore) Add(params CAParams) {
	if s.store == nil {
		s.store = make(map[string]CAParams)
	}
	s.store[params.Issuer.String()] = params
}

// A TrustAnchorIdentifier (TAI) is used to identify a CA, or a specific batch.
//
// TAI are OIDs relative to the Private Enterprise Numbers (PEN)
// arc 1.3.6.1.4.1.
type TrustAnchorIdentifier struct {
	Issuer      RelativeOID
	BatchNumber uint32
}

type RelativeOID []byte

func (tai *TrustAnchorIdentifier) ProofType(store CAStore) ProofType {
	return store.Lookup(tai.Issuer).ProofType
}

func (oid RelativeOID) segments() []uint32 {
	var res []uint32
	cur := uint32(0)
	for i := 0; i < len(oid); i++ {
		cur = (cur << 7) | uint32(oid[i]&0x7f)

		if oid[i]&0x80 == 0 {
			res = append(res, cur)
			cur = 0
		}
	}
	return res
}

func (tai *TrustAnchorIdentifier) UnmarshalBinary(buf []byte) error {
	s := cryptobyte.String(buf)
	err := tai.unmarshal(&s)
	if err != nil {
		return err
	}
	if !s.Empty() {
		return ErrExtraBytes
	}
	return nil
}

func (oid RelativeOID) String() string {
	if oid == nil {
		return "nil"
	}

	var buf bytes.Buffer

	first := true
	for _, s := range oid.segments() {
		if !first {
			_, _ = fmt.Fprintf(&buf, ".")
		}
		first = false
		_, _ = fmt.Fprintf(&buf, "%d", s)
	}
	return buf.String()
}

func (oid *RelativeOID) FromSegments(segments []uint32) error {
	var buf bytes.Buffer
	for _, v := range segments {
		for j := 4; j >= 0; j-- {
			cur := v >> (j * 7)
			if cur != 0 || j == 0 {
				toWrite := byte(cur & 0x7f)
				if j != 0 {
					toWrite |= 0x80
				}
				buf.WriteByte(toWrite)
			}
		}
	}
	*oid = buf.Bytes()
	if len(*oid) > 255 {
		return errors.New("OID: over 255 bytes")
	}
	return nil
}

func (oid *RelativeOID) UnmarshalText(text []byte) error {
	bits := strings.Split(string(text), ".")
	var segments []uint32
	for i, bit := range bits {
		v, err := strconv.ParseUint(bit, 10, 32)
		if err != nil {
			return fmt.Errorf("OID: subidentifier %d: %v", i, err)
		}
		segments = append(segments, uint32(v))
	}
	err := oid.FromSegments(segments)
	if err != nil {
		return err
	}
	if len(*oid) > 255 {
		return errors.New("OID: over 255 bytes")
	}
	return nil
}

func (oid RelativeOID) MarshalBinary() ([]byte, error) {
	if len(oid) == 0 {
		return nil, errors.New("can't marshal uninitialized RelativeOID")
	}

	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(oid)
	})
	return b.Bytes()
}

func (oid *RelativeOID) Equal(rhs *RelativeOID) bool {
	if rhs == nil {
		return false
	}
	if len(*oid) == len(*rhs) {
		for i, v := range *oid {
			if v != (*rhs)[i] {
				return false
			}
		}
		return true
	}
	return false
}

func (tai TrustAnchorIdentifier) MarshalBinary() ([]byte, error) {
	if len(tai.Issuer) == 0 {
		return nil, errors.New("can't marshal uninitialized TrustAnchorIdentifier")
	}
	batch := RelativeOID{}
	err := batch.FromSegments([]uint32{tai.BatchNumber})
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(tai.Issuer)
		b.AddBytes(batch)
	})
	return b.Bytes()
}

func (tai *TrustAnchorIdentifier) unmarshal(s *cryptobyte.String) error {
	var oidBytes []byte
	if !copyUint8LengthPrefixed(s, &oidBytes) || len(oidBytes) == 0 {
		return ErrTruncated
	}

	cur := uint64(0)
	child := 0

	for i := 0; i < len(oidBytes); i++ {
		if cur == 0 && (oidBytes)[i] == 0x80 {
			return errors.New("TrustAnchorIdentifier: not normalized; starts with 0x80")
		}
		cur = (cur << 7) | uint64((oidBytes)[i]&0x7f)

		if cur > 0xffffffff {
			return fmt.Errorf("TrustAnchorIdentifier: overflow of sub-identifier %d", child)
		}

		if (oidBytes)[i]&0x80 == 0 {
			cur = 0
			child++
		} else if i == len(oidBytes)-1 {
			return errors.New("TrustAnchorIdentifier: ends on continuation")
		}
	}

	oid := RelativeOID(oidBytes)
	segments := oid.segments()
	tai.BatchNumber = segments[len(segments)-1]
	err := oid.FromSegments(segments[:len(segments)-1])
	if err != nil {
		return err
	}
	tai.Issuer = oid
	return nil
}

// Same as BatchEntry, but keeps track of offset within stream it was
// unmarshalled from. Used to create index.
type BatchEntryWithOffset struct {
	BatchEntry
	Offset int
}

func (be *BatchEntryWithOffset) unmarshal(s *cryptobyte.String) error {
	return be.BatchEntry.unmarshal(s)
}
func (be *BatchEntryWithOffset) maxSize() int {
	return be.BatchEntry.maxSize()
}
func (be *BatchEntryWithOffset) recordOffset(offset int) {
	be.Offset = offset
}

// Same as EvidenceList, but keeps track of offset within stream it was
// unmarshalled from. Used to create index.
type EvidenceListWithOffset struct {
	EvidenceList
	Offset int
}

func (ev *EvidenceListWithOffset) unmarshal(s *cryptobyte.String) error {
	return ev.EvidenceList.unmarshal(s)
}
func (ev *EvidenceListWithOffset) maxSize() int {
	return ev.EvidenceList.maxSize()
}
func (ev *EvidenceListWithOffset) recordOffset(offset int) {
	ev.Offset = offset
}
