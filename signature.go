package mtc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

// Signing public key with specific hash and options.
type Verifier interface {
	Verify(message, signature []byte) error
	Scheme() SignatureScheme
	Bytes() []byte
}

type pssVerifier struct {
	pk     *rsa.PublicKey
	hash   crypto.Hash
	scheme SignatureScheme
}

func (v *pssVerifier) Bytes() []byte {
	return x509.MarshalPKCS1PublicKey(v.pk)
}
func (v *pssVerifier) Scheme() SignatureScheme { return v.scheme }
func (v *pssVerifier) Verify(msg, sig []byte) error {
	h := v.hash.New()
	_, _ = h.Write(msg)
	hashed := h.Sum(nil)
	signOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	return rsa.VerifyPSS(v.pk, v.hash, hashed, sig, signOpts)
}

type ed25519Verifier ed25519.PublicKey

func (v ed25519Verifier) Bytes() []byte {
	ret := make([]byte, ed25519.PublicKeySize)
	copy(ret, v)
	return ret
}
func (v ed25519Verifier) Scheme() SignatureScheme { return tlsEd25519 }
func (v ed25519Verifier) Verify(msg, sig []byte) error {
	if ed25519.Verify((ed25519.PublicKey)(v), msg, sig) {
		return nil
	}
	return errors.New("ed25519 verification failed")
}

type ecdsaVerifier struct {
	pk     *ecdsa.PublicKey
	hash   crypto.Hash
	scheme SignatureScheme
}

func (v *ecdsaVerifier) Bytes() []byte {
	return elliptic.Marshal(v.pk.Curve, v.pk.X, v.pk.Y)
}
func (v *ecdsaVerifier) Scheme() SignatureScheme { return v.scheme }
func (v *ecdsaVerifier) Verify(msg, sig []byte) error {
	h := v.hash.New()
	_, _ = h.Write(msg)
	hashed := h.Sum(nil)
	if ecdsa.VerifyASN1(v.pk, hashed, sig) {
		return nil
	}
	return errors.New("ecdsa verification failed")
}

func signatureSchemeToHash(scheme SignatureScheme) (crypto.Hash, error) {
	switch scheme {
	case tlsPSSWithSHA256, tlsECDSAWithP256AndSHA256:
		return crypto.SHA256, nil
	case tlsPSSWithSHA384, tlsECDSAWithP384AndSHA384:
		return crypto.SHA384, nil
	case tlsPSSWithSHA512, tlsECDSAWithP521AndSHA512:
		return crypto.SHA512, nil
	case tlsEd25519:
		return 0, nil
	}
	return 0, errors.New("Unsupported SignatureScheme")
}

func signatureSchemeToCurve(scheme SignatureScheme) elliptic.Curve {
	switch scheme {
	case tlsECDSAWithP256AndSHA256:
		return elliptic.P256()
	case tlsECDSAWithP384AndSHA384:
		return elliptic.P384()
	case tlsECDSAWithP521AndSHA512:
		return elliptic.P521()
	}
	panic("Unsupported curve")
}

func NewVerifier(scheme SignatureScheme, pk crypto.PublicKey) (
	Verifier, error) {
	h, err := signatureSchemeToHash(scheme)
	if err != nil {
		return nil, err
	}

	switch scheme {
	case tlsPSSWithSHA256, tlsPSSWithSHA384, tlsPSSWithSHA512:
		rpk, ok := pk.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("Expected *rsa.PublicKey")
		}
		return &pssVerifier{hash: h, pk: rpk, scheme: scheme}, nil

	case tlsEd25519:
		epk, ok := pk.(ed25519.PublicKey)
		if !ok || len(epk) != ed25519.PublicKeySize {
			return nil, errors.New("Expected ed25519.PublicKey")
		}
		return ed25519Verifier(epk), nil
	case tlsECDSAWithP256AndSHA256, tlsECDSAWithP384AndSHA384, tlsECDSAWithP521AndSHA512:
		epk, ok := pk.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("Expected *ecdsa.PublicKey")
		}
		curve := signatureSchemeToCurve(scheme)
		if curve != epk.Curve {
			return nil, fmt.Errorf("Expected curve %v, got %v", curve, epk.Curve)
		}
		return &ecdsaVerifier{hash: h, pk: epk, scheme: scheme}, nil
	default:
		return nil, errors.New("Unsupported SignatureScheme")
	}
}

func UnmarshalVerifier(scheme SignatureScheme, data []byte) (
	Verifier, error) {
	h, err := signatureSchemeToHash(scheme)
	if err != nil {
		return nil, err
	}

	switch scheme {
	case tlsPSSWithSHA256, tlsPSSWithSHA384, tlsPSSWithSHA512:
		pk, err := x509.ParsePKCS1PublicKey(data)
		if err != nil {
			return nil, err
		}
		return &pssVerifier{hash: h, pk: pk, scheme: scheme}, nil
	case tlsEd25519:
		if len(data) != ed25519.PublicKeySize {
			return nil, errors.New("Wrong length for ed25519 public key")
		}
		return ed25519Verifier(data), nil
	case tlsECDSAWithP521AndSHA512, tlsECDSAWithP384AndSHA384, tlsECDSAWithP256AndSHA256:
		curve := signatureSchemeToCurve(scheme)
		x, y := elliptic.Unmarshal(curve, data)
		if x == nil {
			return nil, errors.New("Failed to unmarshal ecdsa public key")
		}
		return &ecdsaVerifier{
			hash: h,
			pk: &ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			},
			scheme: scheme,
		}, nil
	default:
		return nil, errors.New("Unsupported SignatureScheme")
	}
}
