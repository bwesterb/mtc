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

	dil5 "github.com/cloudflare/circl/sign/dilithium/mode5"
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
func (v ed25519Verifier) Scheme() SignatureScheme { return TLSEd25519 }
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

type dil5Verifier dil5.PublicKey

func (v *dil5Verifier) Bytes() []byte {
	var ret [dil5.PublicKeySize]byte
	(*dil5.PublicKey)(v).Pack(&ret)
	return ret[:]
}
func (v *dil5Verifier) Scheme() SignatureScheme { return TLSDilitihium5r3 }
func (v *dil5Verifier) Verify(msg, sig []byte) error {
	if dil5.Verify((*dil5.PublicKey)(v), msg, sig) {
		return nil
	}

	return errors.New("dilithium5 verification failed")
}

func signatureSchemeToHash(scheme SignatureScheme) (crypto.Hash, error) {
	switch scheme {
	case TLSPSSWithSHA256, TLSECDSAWithP256AndSHA256:
		return crypto.SHA256, nil
	case TLSPSSWithSHA384, TLSECDSAWithP384AndSHA384:
		return crypto.SHA384, nil
	case TLSPSSWithSHA512, TLSECDSAWithP521AndSHA512:
		return crypto.SHA512, nil
	case TLSEd25519, TLSDilitihium5r3:
		return 0, nil
	}
	return 0, errors.New("Unsupported SignatureScheme")
}

func signatureSchemeToCurve(scheme SignatureScheme) elliptic.Curve {
	switch scheme {
	case TLSECDSAWithP256AndSHA256:
		return elliptic.P256()
	case TLSECDSAWithP384AndSHA384:
		return elliptic.P384()
	case TLSECDSAWithP521AndSHA512:
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
	case TLSPSSWithSHA256, TLSPSSWithSHA384, TLSPSSWithSHA512:
		rpk, ok := pk.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("Expected *rsa.PublicKey")
		}
		return &pssVerifier{hash: h, pk: rpk, scheme: scheme}, nil

	case TLSEd25519:
		epk, ok := pk.(ed25519.PublicKey)
		if !ok || len(epk) != ed25519.PublicKeySize {
			return nil, errors.New("Expected ed25519.PublicKey")
		}
		return ed25519Verifier(epk), nil
	case TLSECDSAWithP256AndSHA256, TLSECDSAWithP384AndSHA384, TLSECDSAWithP521AndSHA512:
		epk, ok := pk.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("Expected *ecdsa.PublicKey")
		}
		curve := signatureSchemeToCurve(scheme)
		if curve != epk.Curve {
			return nil, fmt.Errorf("Expected curve %v, got %v", curve, epk.Curve)
		}
		return &ecdsaVerifier{hash: h, pk: epk, scheme: scheme}, nil
	case TLSDilitihium5r3:
		dpk, ok := pk.(*dil5.PublicKey)
		if !ok {
			return nil, errors.New("Expected github.com/cloudflare/circl/sign/dilithium/mode5.*PublicKey")
		}
		return (*dil5Verifier)(dpk), nil
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
	case TLSPSSWithSHA256, TLSPSSWithSHA384, TLSPSSWithSHA512:
		pk, err := x509.ParsePKCS1PublicKey(data)
		if err != nil {
			return nil, err
		}
		return &pssVerifier{hash: h, pk: pk, scheme: scheme}, nil
	case TLSEd25519:
		if len(data) != ed25519.PublicKeySize {
			return nil, errors.New("Wrong length for ed25519 public key")
		}
		return ed25519Verifier(data), nil
	case TLSECDSAWithP521AndSHA512, TLSECDSAWithP384AndSHA384, TLSECDSAWithP256AndSHA256:
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
	case TLSDilitihium5r3:
		var (
			buf [dil5.PublicKeySize]byte
			pk  dil5.PublicKey
		)
		if len(data) != dil5.PublicKeySize {
			return nil, errors.New("Wrong length for dilithium5 public key")
		}
		copy(buf[:], data)
		pk.Unpack(&buf)
		return (*dil5Verifier)(&pk), nil
	default:
		return nil, errors.New("Unsupported SignatureScheme")
	}
}

// Signing private key with specific hash and options.
type Signer interface {
	Sign(message []byte) []byte
	Scheme() SignatureScheme
	Bytes() []byte
}

type dil5Signer dil5.PrivateKey

func (s *dil5Signer) Bytes() []byte {
	var ret [dil5.PrivateKeySize]byte
	(*dil5.PrivateKey)(s).Pack(&ret)
	return ret[:]
}
func (s *dil5Signer) Scheme() SignatureScheme { return TLSDilitihium5r3 }
func (s *dil5Signer) Sign(msg []byte) []byte {
	var sig [dil5.SignatureSize]byte
	dil5.SignTo((*dil5.PrivateKey)(s), msg, sig[:])
	return sig[:]
}

func UnmarshalSigner(scheme SignatureScheme, data []byte) (
	Signer, error) {
	_, err := signatureSchemeToHash(scheme)
	if err != nil {
		return nil, err
	}

	switch scheme {
	case TLSDilitihium5r3:
		var (
			buf [dil5.PrivateKeySize]byte
			sk  dil5.PrivateKey
		)
		if len(data) != dil5.PrivateKeySize {
			return nil, errors.New("Wrong length for dilithium5 private key")
		}
		copy(buf[:], data)
		sk.Unpack(&buf)
		return (*dil5Signer)(&sk), nil
	default:
		return nil, errors.New("Unsupported SignatureScheme")
	}
}

func GenerateSigningKeypair(scheme SignatureScheme) (Signer, Verifier, error) {
	_, err := signatureSchemeToHash(scheme)
	if err != nil {
		return nil, nil, err
	}

	switch scheme {
	case TLSDilitihium5r3:
		pk, sk, err := dil5.GenerateKey(nil)
		if err != nil {
			return nil, nil, err
		}
		return (*dil5Signer)(sk), (*dil5Verifier)(pk), nil
	default:
		return nil, nil, errors.New("Unsupported SignatureScheme")
	}
}

func (s SignatureScheme) String() string {
	switch s {
	case TLSPSSWithSHA256:
		return "rsa-sha256"
	case TLSPSSWithSHA384:
		return "rsa-sha384"
	case TLSPSSWithSHA512:
		return "rsa-sha512"
	case TLSECDSAWithP256AndSHA256:
		return "p256"
	case TLSECDSAWithP384AndSHA384:
		return "p384"
	case TLSECDSAWithP521AndSHA512:
		return "p521"
	case TLSEd25519:
		return "ed25519"
	case TLSDilitihium5r3:
		return "dilithium5"
	}
	return fmt.Sprintf("unknown:%d", uint16(s))
}

func SignatureSchemeFromString(s string) SignatureScheme {
	switch s {
	case "rsa-sha256":
		return TLSPSSWithSHA256
	case "rsa-sha384":
		return TLSPSSWithSHA384
	case "rsa-sha512":
		return TLSPSSWithSHA512
	case "p256":
		return TLSECDSAWithP256AndSHA256
	case "p384":
		return TLSECDSAWithP384AndSHA384
	case "p521":
		return TLSECDSAWithP521AndSHA512
	case "dilithium5":
		return TLSDilitihium5r3
	case "ed25519":
		return TLSEd25519
	}
	return 0
}

// Returns valid signature schemes for given public key
func SignatureSchemesFor(pk crypto.PublicKey) []SignatureScheme {
	switch pk := pk.(type) {
	case *rsa.PublicKey:
		return []SignatureScheme{
			TLSPSSWithSHA256,
			TLSPSSWithSHA384,
			TLSPSSWithSHA512,
		}
	case *ecdsa.PublicKey:
		switch pk.Curve.Params().Name {
		case "P-256":
			return []SignatureScheme{TLSECDSAWithP256AndSHA256}
		case "P-384":
			return []SignatureScheme{TLSECDSAWithP384AndSHA384}
		case "P-521":
			return []SignatureScheme{TLSECDSAWithP521AndSHA512}
		}
		return []SignatureScheme{}
	case ed25519.PublicKey:
		return []SignatureScheme{TLSEd25519}
	case *dil5.PublicKey:
		return []SignatureScheme{TLSDilitihium5r3}
	}
	return []SignatureScheme{}
}
