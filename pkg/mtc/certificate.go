package mtc

import (
	"fmt"
	"golang.org/x/crypto/cryptobyte"
)

type BikeshedCertificate struct {
	Assertion Assertion
	Proof     Proof
}

func (c *BikeshedCertificate) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	buf, err := c.Assertion.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Assertion: %w", err)
	}
	b.AddBytes(buf)

	tai := c.Proof.TrustAnchorIdentifier()
	buf, err = tai.MarshalBinary()
	b.AddBytes(buf)
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
	if !s.ReadUint16LengthPrefixed(&proofInfo) {
		return ErrTruncated
	}
	if !s.Empty() {
		return ErrExtraBytes
	}
	switch tai.ProofType(caStore) {
	case MerkleTreeProofType:
		proof := &MerkleTreeProof{}
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
		anchor: tai,
		info:   proofInfo,
	}
	return nil
}
