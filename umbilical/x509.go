// Package umbilical has the temporary logic to back an MTC with an existing
// X509 certificate chain.
package umbilical

import (
	"time"

	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/umbilical/revocation"

	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Suggests an Assertion from an existing X509 certificate.
//
// If non-zero, uses the given signature scheme.
func SuggestedAssertionFromX509(cert *x509.Certificate,
	scheme mtc.SignatureScheme) (
	a mtc.Assertion, err error) {
	for _, name := range cert.DNSNames {
		wildcard := false

		if strings.HasPrefix(name, "*.") {
			wildcard = true
			name = name[2:]
		}

		if strings.Contains(name, "*") {
			continue
		}

		if wildcard {
			a.Claims.DNSWildcard = append(a.Claims.DNSWildcard, name)
		} else {
			a.Claims.DNS = append(a.Claims.DNS, name)
		}
	}

	for _, ip := range cert.IPAddresses {
		ip4 := ip.To4()
		if ip4 != nil {
			a.Claims.IPv4 = append(a.Claims.IPv4, ip4)
		} else {
			a.Claims.IPv6 = append(a.Claims.IPv6, ip)
		}
	}

	if scheme == 0 {
		schemes := mtc.SignatureSchemesFor(cert.PublicKey)
		if len(schemes) == 0 {
			err = errors.New("Unsupported public key type")
			return
		}
		scheme = schemes[0]
	}

	a.Subject, err = mtc.NewTLSSubject(scheme, cert.PublicKey)

	return
}

// Pulls certificate chain served by TLS server.
func GetChainFromTLSServer(addr string) (chain []*x509.Certificate, err error) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		conn, err2 := tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			VerifyConnection: func(state tls.ConnectionState) error {
				chain = state.PeerCertificates
				return nil
			},
		})
		if err2 != nil {
			err = fmt.Errorf("tls.Dial(%s): %v", addr, err2)
		} else {
			conn.Close()
		}
		wg.Done()
	}()
	wg.Wait()
	return
}

// Checks whether the given assertion (to be) issued is consistent with
// the given X.509 certificate chain and accepted roots for the given validity
// interval. The assertion is allowed to cover less than the certificate:
// eg, only example.com where the certificate covers some.example.com too.
//
// On the other hand, we are more strict than is perhaps required. For
// instance, we do not allow an assertion for some.example.com to be backed
// by a wildcard certificate for *.example.com.
// Also we require basically the same chain to be valid for the full
// duration of the assertion.
//
// If rc is set, checks whether the certificate is revoked. Does not check
// revocation of intermediates.
//
// If consistent, returns one or more verified chains.
func CheckAssertionValidForX509(a mtc.Assertion, start, end time.Time,
	chain []*x509.Certificate, roots *x509.CertPool, rc *revocation.Checker) (
	[][]*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, errors.New("empty chain")
	}

	cert := chain[0]

	// Check if the claims are covered by the certificate.
	for _, ip := range slices.Concat(a.Claims.IPv4, a.Claims.IPv6) {
		ok := false
		for _, ip2 := range cert.IPAddresses {
			if ip2.Equal(ip) {
				ok = true
				break
			}
		}

		if !ok {
			return nil, fmt.Errorf("X.509 certificate not valid for %s", ip)
		}
	}

	got := make(map[string]struct{})
	for _, name := range cert.DNSNames {
		got[name] = struct{}{}
	}
	for _, name := range a.Claims.DNS {
		if _, ok := got[name]; !ok {
			return nil, fmt.Errorf(
				"No exact match for %s in provided X.509 cert",
				name,
			)
		}
	}
	for _, name := range a.Claims.DNSWildcard {
		if _, ok := got["*."+name]; !ok {
			return nil, fmt.Errorf(
				"No exact match for *.%s in provided X.509 cert",
				name,
			)
		}
	}

	if len(a.Claims.Unknown) != 0 {
		return nil, errors.New("unknown claims")
	}

	// Check if subjects match.
	if a.Subject.Type() != mtc.TLSSubjectType {
		return nil, errors.New("Expected TLSSubjectType")
	}
	subjVerifier, err := a.Subject.(*mtc.TLSSubject).Verifier()
	if err != nil {
		return nil, fmt.Errorf("Assertion Subject: %w", err)
	}

	certSubject, err := mtc.NewTLSSubject(subjVerifier.Scheme(), cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("NewTLSSubject(X.509 public key): %w", err)
	}
	if !bytes.Equal(certSubject.Info(), a.Subject.Info()) {
		return nil, fmt.Errorf("Subjects don't match")
	}

	// Verify chain at the start of the validity period
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   start,
	}
	for _, cert2 := range chain[1:] {
		opts.Intermediates.AddCert(cert2)
	}
	chains, err := cert.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("X.509 Verify: %w", err)
	}

	var ret [][]*x509.Certificate
	var errs []error

	// Verify each chain at the end of the validity period
	for _, candidateChain := range chains {
		opts = x509.VerifyOptions{
			Roots:         x509.NewCertPool(),
			Intermediates: x509.NewCertPool(),
			CurrentTime:   end,
		}

		for _, cert2 := range candidateChain[1 : len(candidateChain)-1] {
			opts.Intermediates.AddCert(cert2)
		}
		opts.Roots.AddCert(candidateChain[len(candidateChain)-1])
		_, err := cert.Verify(opts)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ret = append(ret, candidateChain)
	}

	if len(ret) == 0 {
		return nil, fmt.Errorf(
			"Could not find chain valid during lifetime of certificate: %w",
			errors.Join(errs...),
		)
	}

	if rc != nil {
		revoked, err := rc.Revoked(ret[0][0], ret[0][1])
		if err != nil {
			return nil, fmt.Errorf("checking revocation: %w", err)
		}

		if revoked {
			return nil, errors.New("certificate is revoked")
		}
	}

	return ret, nil
}
