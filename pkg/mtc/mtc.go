package mtc

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// CAParams holds the public parameters of a Merkle Tree CA
type CAParams struct {
	Issuer             RelativeOID
	PublicKey          Verifier
	ProofType          ProofType
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

// SignatureScheme is a copy of tls.SignatureScheme to prevent cycling dependencies
// and adds TLSDilitihium5r3 as an option
type SignatureScheme uint16

const (
	TLSPSSWithSHA256          SignatureScheme = 0x0804
	TLSPSSWithSHA384          SignatureScheme = 0x0805
	TLSPSSWithSHA512          SignatureScheme = 0x0806
	TLSECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	TLSECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	TLSECDSAWithP521AndSHA512 SignatureScheme = 0x0603
	TLSEd25519                SignatureScheme = 0x0807

	// TLSDilitihium5r3 is added for testing.
	// We use round 3 Dilithium5 with a codepoint in the
	// private use region.
	// For production SPHINCS⁺-128s would be a better choice.
	TLSDilitihium5r3 SignatureScheme = 0xfe3c
)

type ValidityWindow struct {
	BatchNumber uint32
	TreeHeads   []byte
}

type SignedValidityWindow struct {
	ValidityWindow
	Signature []byte
}

type Batch struct {
	CA     *CAParams
	Number uint32
}

// BatchRange returns the range of batch numbers Begin, …, End-1.
type BatchRange struct {
	Begin uint32
	End   uint32
}

func (r BatchRange) Len() int {
	return int(r.End) - int(r.Begin)
}

// AreAllPast returns whether each batch in the range is after the given batch
func (r BatchRange) AreAllPast(batch uint32) bool {
	if r.Begin == r.End {
		return true
	}
	return batch < r.Begin
}

// Contains returns whether r contains the batch with the given number.
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

// Tree is a merkle tree built upon the assertions of a batch.
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

// WriteTo writes the tree to w
func (t *Tree) WriteTo(w io.Writer) (int64, error) {
	var b cryptobyte.Builder
	b.AddUint64(t.nLeaves)
	buf, err := b.Bytes()
	if err != nil {
		return 0, err
	}
	written1, err := w.Write(buf)
	if err != nil {
		return 0, err
	}
	written2, err := w.Write(t.buf)
	if err != nil {
		return 0, err
	}
	return int64(written1 + written2), nil
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

// StoredBatches returns batches that are expected to be available at this CA, at the given time.
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

// NextBatchAt returns the time when the next batch starts.
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

// ActiveBatches returns batches that are non-expired, and either issued or ready, at the given time.
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
		!s.ReadUint16((*uint16)(&p.ProofType)) ||
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

	p.Issuer = issuerBuf
	p.HttpServer = string(httpServerBuf)
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

// PreEpochRoots returns the roots of the validity window prior the epoch.
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
	toSign, err := w.ValidityWindow.LabeledValidityWindow(p)
	if err != nil {
		return err
	}
	return p.PublicKey.Verify(toSign, w.Signature)
}

// UnmarshalBinaryWithoutVerification is like UnmarshalBinary() but doesn't check the signature.
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

// LabeledValidityWindow returns the corresponding marshaled LabeledValidityWindow, which
// is signed by the CA.
func (w *ValidityWindow) LabeledValidityWindow(ca *CAParams) ([]byte, error) {
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
func (p *CAParams) newTreeHeads(prevHeads, root []byte) ([]byte, error) {
	expected := HashLen * p.ValidityWindowSize
	if len(prevHeads) != int(expected) {
		return nil, fmt.Errorf(
			"expected prevHeads to be %d bytes; got %d bytes instead",
			expected,
			len(prevHeads),
		)
	}
	if len(root) != HashLen {
		return nil, fmt.Errorf(
			"expected root to be %d bytes; got %d bytes instead",
			expected,
			len(root),
		)
	}
	return append(prevHeads[HashLen:], root...), nil
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
	toSign, err := w.ValidityWindow.LabeledValidityWindow(batch.CA)
	if err != nil {
		return SignedValidityWindow{}, fmt.Errorf(
			"computing LabeledValidityWindow: %w",
			err,
		)
	}
	w.Signature = signer.Sign(toSign)
	return w, nil
}

func (t *Tree) LeafCount() uint64 {
	return t.nLeaves
}

// Root returns the root of the tree
func (t *Tree) Root() []byte {
	return t.buf[len(t.buf)-HashLen : len(t.buf)]
}

// AuthenticationPath returns the authentication path proving that the leaf at the given index
// is included in the Merkle tree.
func (t *Tree) AuthenticationPath(index uint64) ([]byte, error) {
	if index >= t.nLeaves {
		return nil, errors.New("tree index out of range")
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

// hashLeaves reads a stream of AbridgedAssertions from in, hashes them, and
// returns the concatenated hashes.
func (batch *Batch) hashLeaves(r io.Reader) ([]byte, error) {
	ret := &bytes.Buffer{}

	// First, read all abridged assertions and hash them.
	var index uint64
	hash := make([]byte, HashLen)

	err := unmarshal(r, func(_ int, aa *AbridgedAssertion) error {
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

// UnmarshalAbridgedAssertions unmarshalls AbridgedAssertion from r and calls f for each, with
// the offset in the stream as first argument, and the abridged
// assertion as second argument.
//
// Returns early one rror.
func UnmarshalAbridgedAssertions(r io.Reader,
	f func(int, *AbridgedAssertion) error) error {
	return unmarshal(r, f)
}

// ComputeRootFromAuthenticationPath computes the batch root from the authentication path.
//
// To verify a certificate/proof, use VerifyAuthenticationPath instead.
func (batch *Batch) ComputeRootFromAuthenticationPath(index uint64,
	path []byte, aa *AbridgedAssertion) ([]byte, error) {
	h := make([]byte, HashLen)
	if err := aa.Hash(h[:], batch, index); err != nil {
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
		return nil, fmt.Errorf("authentication path too short")
	}

	return h, nil
}

// VerifyAuthenticationPath checks the validity of the authentication path.
//
// Return nil on a valid authentication path.
func (batch *Batch) VerifyAuthenticationPath(index uint64, path, root []byte,
	aa *AbridgedAssertion) error {

	h, err := batch.ComputeRootFromAuthenticationPath(index, path, aa)
	if err != nil {
		return err
	}

	if !bytes.Equal(root, h) {
		return fmt.Errorf("authentication path invalid")
	}

	return nil
}

func (batch *Batch) hashNode(out, left, right []byte, index uint64,
	level uint8) error {
	var b cryptobyte.Builder

	b.AddUint8(1)
	var issuer, err = batch.CA.Issuer.MarshalBinary()
	if err != nil {
		return nil
	}
	b.AddBytes(issuer)
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
	var issuer, err = batch.CA.Issuer.MarshalBinary()
	if err != nil {
		return err
	}
	b.AddBytes(issuer)
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

// ComputeTree computes the Merkle tree from a stream of AbridgedAssertion from in.
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
		offset       = 0 // offset of current level in buf
	)

	nNodes := nLeaves
	for nNodes != 1 {
		// Add empty node if the number of leaves on this level is odd
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
