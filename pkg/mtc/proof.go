package mtc

import (
	"fmt"
	"golang.org/x/crypto/cryptobyte"
)

type ProofType uint16

const (
	MerkleTreeProofType ProofType = iota
)

type Proof interface {
	TrustAnchorIdentifier() TrustAnchorIdentifier
	Info() []byte
}

type MerkleTreeProof struct {
	anchor TrustAnchorIdentifier
	index  uint64
	path   []byte
}

type UnknownProof struct {
	anchor TrustAnchorIdentifier
	info   []byte
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
		// Can only happen if the path is too long, but we checked for this.
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

func (p *UnknownProof) Info() []byte {
	return p.info
}

func (p ProofType) String() string {
	switch p {
	case MerkleTreeProofType:
		return "merkle_tree_sha256"
	default:
		return fmt.Sprintf("ProofType(%d)", p)
	}
}

func NewMerkleTreeProof(batch *Batch, index uint64, path []byte) *MerkleTreeProof {
	return &MerkleTreeProof{
		anchor: batch.Anchor(),
		index:  index,
		path:   path,
	}
}
