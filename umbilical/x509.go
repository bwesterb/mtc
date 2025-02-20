// Package umbilical has the temporary logic to back an MTC with an existing
// X509 certificate chain.
package umbilical

import (
	"github.com/bwesterb/mtc"

	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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
