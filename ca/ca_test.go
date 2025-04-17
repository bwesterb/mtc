package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bwesterb/mtc"
)

// testCA is a Merkle Tree CA that runs in memory.
type testCA struct {
	*Handle
	path string
}

// newTestCA creates a CA in a temporary directory. The caller should call
// `Close()` in order to delete the directory once the test is finished.
func newTestCA(t *testing.T) *testCA {
	path, err := os.MkdirTemp("", "test-mtca-*")
	if err != nil {
		t.Fatal(err)
	}

	success := false
	defer func() {
		if !success {
			if err := os.RemoveAll(path); err != nil {
				panic(err)
			}
		}
	}()

	issuer := mtc.RelativeOID{}
	err = issuer.UnmarshalText([]byte("1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}

	handle, err := New(path, NewOpts{
		Issuer:       issuer,
		ServerPrefix: "ca.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	success = true
	return &testCA{
		handle,
		path,
	}
}

func (ca *testCA) Close() {
	ca.Handle.Close()
	if err := os.RemoveAll(ca.path); err != nil {
		panic(err)
	}
}

func createVerifyTest(t *testing.T) (*mtc.BikeshedCertificate,
	*mtc.SignedValidityWindow, mtc.CAParams) {
	ca := newTestCA(t)
	defer ca.Close()

	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	subject, err := mtc.NewTLSSubject(
		mtc.TLSECDSAWithP256AndSHA256,
		sk.Public(),
	)
	if err != nil {
		t.Fatal(err)
	}

	assertion := mtc.Assertion{
		Subject: subject,
		Claims: mtc.Claims{
			DNS: []string{"example.org"},
		},
	}

	assertionRequest := &mtc.AssertionRequest{
		Assertion: assertion,
	}
	err = assertionRequest.Check()
	if err != nil {
		t.Fatal(err)
	}

	err = ca.Queue(*assertionRequest)
	if err != nil {
		t.Fatal(err)
	}

	err = ca.Issue()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := ca.CertificateFor(assertionRequest.Assertion)
	if err != nil {
		t.Fatal(err)
	}

	signedValidityWindow, err := ca.SignedValidityWindowForBatch(0)
	if err != nil {
		t.Fatal(err)
	}

	return cert, signedValidityWindow, ca.Params()
}

func TestVerifyOk(t *testing.T) {
	cert, signedValidityWindow, ca := createVerifyTest(t)
	err := cert.Verify(mtc.VerifyOptions{
		CA:             &ca,
		ValidityWindow: &signedValidityWindow.ValidityWindow,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyErrorExpired(t *testing.T) {
	cert, signedValidityWindow, ca := createVerifyTest(t)
	// Set the current time to immediately after the certificate's not
	// after parameter.
	now := cert.Proof.NotAfter().Add(1 * time.Microsecond)
	err := cert.Verify(mtc.VerifyOptions{
		CA:             &ca,
		ValidityWindow: &signedValidityWindow.ValidityWindow,
		CurrentTime:    now,
	})
	if err == nil {
		t.Fatal(err)
	} else if !strings.HasPrefix(err.Error(), "Certificate has expired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyErrorNotYetValid(t *testing.T) {
	cert, signedValidityWindow, ca := createVerifyTest(t)
	// Set the current time to immediately before the batch was issued.
	now := time.Unix(int64(ca.StartTime), 0).Add(-1 * time.Microsecond)
	err := cert.Verify(mtc.VerifyOptions{
		CA:             &ca,
		ValidityWindow: &signedValidityWindow.ValidityWindow,
		CurrentTime:    now,
	})
	if err == nil {
		t.Fatal(err)
	} else if !strings.HasPrefix(err.Error(), "Certificate is not yet valid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyErrorInvalidAuthenticationPath(t *testing.T) {
	cert, signedValidityWindow, ca := createVerifyTest(t)
	// Tweak the first bit of the tree head that matches the certificate.
	maxBatchNumber := int(signedValidityWindow.BatchNumber)
	certBatchNumber := int(cert.Proof.TrustAnchorIdentifier().BatchNumber)
	rootIndex := int(mtc.HashLen * (maxBatchNumber - certBatchNumber))
	signedValidityWindow.TreeHeads[rootIndex] ^= 1
	err := cert.Verify(mtc.VerifyOptions{
		CA:             &ca,
		ValidityWindow: &signedValidityWindow.ValidityWindow,
		CurrentTime:    time.Now(),
	})
	if err == nil {
		t.Fatal(err)
	} else if !strings.HasPrefix(err.Error(), "Authentication path invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyErrorInvalidIssuer(t *testing.T) {
	cert, signedValidityWindow, ca := createVerifyTest(t)
	// Tweak the CA issuer OID.
	ca.Issuer = []byte("cool")
	err := cert.Verify(mtc.VerifyOptions{
		CA:             &ca,
		ValidityWindow: &signedValidityWindow.ValidityWindow,
		CurrentTime:    time.Now(),
	})
	if err == nil {
		t.Fatal(err)
	} else if !strings.HasPrefix(err.Error(), "Certificate issuer") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TODO(cjpatton) Add tests for the validity window boundaries:
//
// * TestVerifyErrorValidityWindowTooOld: Certificate verification should fail
//   if certificate batch number is greater than the end of the validity
//   window.
//
// * TestVerifyErrorValidityWindowTooNew: Certificate verification should fail
//   if certificate batch number is less than than the start of the validity
//   window.
//
// * A certificate is accepted by each validity window that contains it.
//   Currently we're only testing one validity window.
//
// We'll need to modify testCA so that we can "fast forward" its internal clock
// to force it to issue multiple batches.
