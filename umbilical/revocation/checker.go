// Package revocation implements the code to check for revocation of X.509
// certificates on demand. It either uses OCSP or CRLs. The latter are
// cached on disk.
package revocation

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

	bolt "go.etcd.io/bbolt"
)

type Config struct {
	// Path to file to use to cache
	Cache string
}

type crlEntry struct {
	Expires  time.Time
	BucketID uint64
}

type Checker struct {
	cache *bolt.DB

	fetchMux sync.Mutex
	// URL -> Cond to wait on a CRL that's currently fetching.
	crlFetching map[string]*sync.Cond
}

func NewChecker(cfg Config) (*Checker, error) {
	var (
		ret Checker
		err error
	)

	ret.cache, err = bolt.Open(cfg.Cache, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("bolt.Open(%s): %w", cfg.Cache, err)
	}

	err = ret.cache.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("crls"))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create crls bucket: %w", err)
	}

	ret.crlFetching = make(map[string]*sync.Cond)

	return &ret, nil
}

// Checks whether the given certificate is revoked by first trying OCSP,
// and then checking CRL.
//
// Warning: make sure you trust the issuer and checked the chain.
// Does not check the signature of the issuer.
func (c *Checker) Revoked(cert, issuer *x509.Certificate) (
	bool, error) {
	if len(cert.OCSPServer) != 0 {
		return c.revokedOCSP(cert, issuer)
	}

	if len(cert.CRLDistributionPoints) != 0 {
		return c.revokedCRL(cert, issuer)
	}

	return true, errors.New("No revocation mechanism available")
}

func sendOCSP(url string, req []byte, cert, issuer *x509.Certificate) (
	*ocsp.Response, error) {
	// TODO Support GET. It might be slightly faster and is easier to cache.
	resp, err := http.Post(
		url,
		"application/ocsp-request",
		bytes.NewBuffer(req),
	)

	if err != nil {
		return nil, fmt.Errorf("POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return ocsp.ParseResponseForCert(bs, cert, issuer)
}

// TODO Cache OCSP. We can use the resp.NextUpdate field.
func (c *Checker) revokedOCSP(cert, issuer *x509.Certificate) (bool, error) {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return true, fmt.Errorf("ocsp.CreateRequest: %w", err)
	}

	ok := false
	var (
		resp *ocsp.Response
		errs []error
	)

	// Although not specified in any standard as far as I know, it seems
	// common to try the OCSP servers in the order they are listed.
	for _, url := range cert.OCSPServer {
		resp, err = sendOCSP(url, req, cert, issuer)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		ok = true
	}

	if !ok {
		return true, fmt.Errorf("No valid OCSP response: %w", errors.Join(errs...))
	}

	switch resp.Status {
	case ocsp.Good:
		return false, nil
	case ocsp.Unknown:
		return true, errors.New("OCSP server doesn't know about certificate")
	case ocsp.Revoked:
		return true, nil
	}

	return true, errors.New("Unrecognized OCSP status")
}

func (c *Checker) checkCRLCache(url string, serial *big.Int) (*bool, error) {
	var (
		rawEntry []byte
		entry    *crlEntry
		ret      *bool
	)
	err := c.cache.View(func(tx *bolt.Tx) error {
		crlsBucket := tx.Bucket([]byte("crls"))
		rawEntry = crlsBucket.Get([]byte(url))

		if rawEntry == nil {
			return nil
		}
		entry = new(crlEntry)
		if err := json.Unmarshal(rawEntry, entry); err != nil {
			return fmt.Errorf("parsing crlentry: %w", err)
		}

		crlBucket := tx.Bucket([]byte(fmt.Sprintf("crl %d", entry.BucketID)))

		val := crlBucket.Get(serial.Bytes())
		ret = new(bool)
		*ret = val != nil
		return nil
	})
	if err != nil {
		return nil, err
	}
	if ret == nil {
		return nil, nil
	}

	if time.Until(entry.Expires) < 0 {
		err := c.cache.Update(func(tx *bolt.Tx) error {
			_ = tx.DeleteBucket([]byte(fmt.Sprintf("crl %d", entry.BucketID)))
			_ = tx.Bucket([]byte("crls")).Delete([]byte(url))
			return nil
		})
		return nil, err
	}

	return ret, nil
}

func fetchCRL(url string, issuer *x509.Certificate) (*x509.RevocationList, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	crl, err := x509.ParseRevocationList(bs)
	if err != nil {
		return nil, fmt.Errorf("parsing CRL: %w", err)
	}

	err = crl.CheckSignatureFrom(issuer)
	if err != nil {
		return nil, fmt.Errorf("CRL signature check: %w", err)
	}

	return crl, nil
}

func (c *Checker) revokedCRL(cert, issuer *x509.Certificate) (bool, error) {
	var errs []error

	for _, url := range cert.CRLDistributionPoints {
		for {
			// Check cache first.
			revoked, err := c.checkCRLCache(url, cert.SerialNumber)
			if err != nil {
				return true, err
			}

			if revoked != nil {
				return *revoked, nil
			}

			// Ok, fetch and cache CRL.
			err = c.fetchAndCacheCRL(url, issuer)
			if err != nil {
				errs = append(errs, err)
				break
			}
		}
	}

	return true, fmt.Errorf("Couldn't fetch CRL: %w", errors.Join(errs...))
}

func (c *Checker) fetchAndCacheCRL(url string, issuer *x509.Certificate) error {
	// First check whether we're already fetching this CRL at the moment. If so,
	// wait and retry reading from cache.
	c.fetchMux.Lock()
	cnd := c.crlFetching[url]
	if cnd != nil {
		cnd.Wait()
		c.fetchMux.Unlock()
		return nil
	}

	cnd = sync.NewCond(&c.fetchMux)
	c.crlFetching[url] = cnd
	c.fetchMux.Unlock()

	crl, err := fetchCRL(url, issuer)
	if err != nil {
		return err
	}

	// TODO Should we have a cache for errors?

	// Check if CRL has expired to prevent an infinite loop with the
	// automatic cache purge.
	if time.Until(crl.NextUpdate).Minutes() < 1 {
		return errors.New("CRL will update within a minute")
	}

	err = c.cache.Update(func(tx *bolt.Tx) error {
		crlsBucket := tx.Bucket([]byte("crls"))

		var entry crlEntry
		entry.Expires = crl.NextUpdate
		entry.BucketID, err = crlsBucket.NextSequence()
		if err != nil {
			return err
		}

		rawEntry, err := json.Marshal(&entry)
		if err != nil {
			return err
		}

		if err := crlsBucket.Put([]byte(url), rawEntry); err != nil {
			return err
		}

		crlBucket, err := tx.CreateBucket(
			[]byte(fmt.Sprintf("crl %d", entry.BucketID)),
		)
		if err != nil {
			return err
		}

		for _, rc := range crl.RevokedCertificateEntries {
			err = crlBucket.Put(rc.SerialNumber.Bytes(), []byte{})
			if err != nil {
				return err
			}
		}

		return nil
	})

	// Wake up waiters
	c.fetchMux.Lock()
	delete(c.crlFetching, url)
	cnd.Broadcast()
	c.fetchMux.Unlock()
	return nil
}

func (c *Checker) Close() {
	c.cache.Close()
}
