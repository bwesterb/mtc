package mtc

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
)

type SubjectType uint16

const (
	TLSSubjectType SubjectType = iota
)

type TLSSubject struct {
	pk     Verifier
	packed []byte
}

// UnknownSubject is used for an unknown (abridged) subject
type UnknownSubject struct {
	typ  SubjectType
	info []byte
}

type SubjectBase interface {
	Type() SubjectType
	Info() []byte
}

type AbridgedSubject interface {
	SubjectBase
}

type AbridgedTLSSubject struct {
	SignatureScheme SignatureScheme
	PublicKeyHash   [HashLen]byte
}

type Subject interface {
	SubjectBase
	Abridge() AbridgedSubject
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

	pk, err := UnmarshalVerifier(scheme, publicKey)
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
		PublicKeyHash:   sha256.Sum256(publicKey),
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
