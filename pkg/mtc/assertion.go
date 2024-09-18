package mtc

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
)

type Assertion struct {
	Subject Subject
	Claims  Claims
}

type AbridgedAssertion struct {
	Subject AbridgedSubject
	Claims  Claims
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
		subjectInfo []byte
		claims      cryptobyte.String
	)
	if !s.ReadUint16((*uint16)(&subjectType)) ||
		!copyUint16LengthPrefixed(s, &subjectInfo) ||
		!s.ReadUint16LengthPrefixed(&claims) {
		return ErrTruncated
	}

	if err := a.Claims.UnmarshalBinary(claims); err != nil {
		return fmt.Errorf("failed to unmarshal claims: %w", err)
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

	if err := a.Claims.UnmarshalBinary(claims); err != nil {
		return fmt.Errorf("failed to unmarshal claims: %w", err)
	}

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
		a.Subject = &subject
	default:
		subjectInfoBuf := make([]byte, len(subjectInfo))
		copy(subjectInfoBuf, subjectInfo)
		a.Subject = &UnknownSubject{
			typ:  subjectType,
			info: subjectInfoBuf,
		}
	}

	return nil
}

// Key computes the key of the AbridgedAssertion used in the index.
func (a *AbridgedAssertion) Key(out []byte) error {
	buf, err := a.MarshalBinary()
	if err != nil {
		return err
	}
	h := sha256.New()
	_, _ = h.Write(buf)
	h.Sum(out[:0])
	return nil
}

// Hash computes the leaf hash of the AbridgedAssertion in the Merkle tree
// computed for the batch.
func (a *AbridgedAssertion) Hash(out []byte, batch *Batch, index uint64) error {
	var b cryptobyte.Builder
	b.AddUint8(2)
	var issuer, err = batch.CA.Issuer.MarshalBinary()
	if err != nil {
		return nil
	}
	b.AddBytes(issuer)
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
