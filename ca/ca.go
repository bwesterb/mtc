package ca

import (
	"errors"
	"fmt"
	"os"
	gopath "path"
	"path/filepath"
	"time"
)

import (
	"github.com/bwesterb/mtc"

	"github.com/nightlyone/lockfile"
)

type NewOpts struct {
	IssuerId   string
	HttpServer string

	// Fields below are optional.

	SignatureScheme mtc.SignatureScheme
	BatchDuration   time.Duration
	Lifetime        time.Duration
}

// Handle for exclusive access to a Merkle Tree CA state.
type Handle struct {
	params mtc.CAParams
	signer mtc.Signer
	flock  lockfile.Lockfile
	path   string
	closed bool
}

func (ca *Handle) Params() mtc.CAParams {
	return ca.params
}

func (ca *Handle) Close() error {
	if ca.closed {
		return errors.New("Already closed")
	}
	ca.closed = true
	return ca.flock.Unlock()
}

// Load private state of Merkle Tree CA, and acquire lock.
//
// Call Handle.Close() when done.
func Open(path string) (*Handle, error) {
	h := Handle{
		path: path,
	}
	if err := h.lock(); err != nil {
		return nil, err
	}
	paramsBuf, err := os.ReadFile(h.paramsPath())
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", h.paramsPath(), err)
	}
	if err := h.params.UnmarshalBinary(paramsBuf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", h.paramsPath(), err)
	}
	skBuf, err := os.ReadFile(h.skPath())
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", h.skPath(), err)
	}
	info, err := os.Stat(h.skPath())
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", h.skPath(), err)
	}
	perm := info.Mode().Perm()
	if perm != 0o400 {
		return nil, fmt.Errorf("incorrect filemode on %s: %o ≠ 0400", h.skPath(), perm)
	}
	h.signer, err = mtc.UnmarshalSigner(h.params.PublicKey.Scheme(), skBuf)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", h.skPath(), err)
	}
	return &h, nil
}

func (h Handle) skPath() string {
	return gopath.Join(h.path, "signing.key")
}

func (h Handle) paramsPath() string {
	return gopath.Join(h.path, "www", "mtc", "v1", "ca-params")
}

func (h *Handle) lock() error {
	lockPath := gopath.Join(h.path, "lock")
	absLockPath, err := filepath.Abs(lockPath)
	if err != nil {
		return fmt.Errorf("filepath.Abs(%s): %w", lockPath, err)
	}
	flock, err := lockfile.New(absLockPath)
	if err != nil {
		return fmt.Errorf("Creating lock %s: %w", absLockPath, err)
	}
	h.flock = flock
	if err := flock.TryLock(); err != nil {
		return fmt.Errorf("Acquiring lock %s: %w", absLockPath, err)
	}
	return nil
}

// Creates a new Merkle Tree CA, and opens it.
//
// Call Handle.Close() when done.
func New(path string, opts NewOpts) (*Handle, error) {
	h := Handle{
		path: path,
	}

	// Set defaults
	if opts.Lifetime == 0 {
		opts.Lifetime = time.Hour * 336
	}
	if opts.BatchDuration == 0 {
		opts.BatchDuration = time.Hour * 1
	}

	// Check options
	if opts.BatchDuration.Nanoseconds()%1000000000 != 0 {
		return nil, errors.New("BatchDuration has to be in full seconds")
	}
	if opts.BatchDuration <= 0 {
		return nil, errors.New("BatchDuration has to be strictly positive")
	}
	if opts.Lifetime < opts.BatchDuration {
		return nil, errors.New("Lifetime has to be larger than BatchDuration")
	}
	if opts.Lifetime.Nanoseconds()%opts.BatchDuration.Nanoseconds() != 0 {
		return nil, errors.New("Lifetime has to be a multiple of BatchDuration")
	}
	h.params.ValidityWindowSize = uint64(opts.Lifetime.Nanoseconds() / opts.BatchDuration.Nanoseconds())
	h.params.BatchDuration = uint64(opts.BatchDuration.Nanoseconds() / 1000000000)
	h.params.Lifetime = uint64(opts.Lifetime.Nanoseconds() / 1000000000)

	h.params.StartTime = uint64(time.Now().Unix())

	h.params.HttpServer = opts.HttpServer
	h.params.IssuerId = opts.IssuerId

	if opts.SignatureScheme == 0 {
		opts.SignatureScheme = mtc.TLSDilitihium5r3
	}

	// Generate keypair
	signer, verifier, err := mtc.GenerateSigningKeypair(opts.SignatureScheme)
	if err != nil {
		return nil, fmt.Errorf("GenerateSigningKeypair: %w", err)
	}
	h.params.PublicKey = verifier
	h.signer = signer

	err = h.params.Validate()
	if err != nil {
		return nil, err
	}

	// Write out. First, create directory if it doesn't exist
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		err = os.MkdirAll(path, 0o755)
		if err != nil {
			return nil, fmt.Errorf("os.MkdirAll(%s): %w", path, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("os.Stat(%s): %w", path, err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", path)
	}

	// Now, attain a file lock.
	if err := h.lock(); err != nil {
		return nil, err
	}
	unlock := true
	defer func() {
		if unlock {
			h.flock.Unlock()
		}
	}()

	// Write out signing key
	if err := os.WriteFile(h.skPath(), signer.Bytes(), 0o400); err != nil {
		return nil, fmt.Errorf("writing %s: %w", h.skPath(), err)
	}

	// Create folders
	pubPath := gopath.Join(path, "www", "mtc", "v1", "batches")
	err = os.MkdirAll(pubPath, 0o755)
	if err != nil {
		return nil, fmt.Errorf("os.MkdirAll(%s): %w", pubPath, err)
	}

	// Queue
	queuePath := gopath.Join(path, "queue")
	if err := os.WriteFile(queuePath, []byte{}, 0o644); err != nil {
		return nil, fmt.Errorf("Writing %s: %w", queuePath, err)
	}

	paramsBuf, err := h.params.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("Marshalling params: %w", err)
	}
	if err := os.WriteFile(h.paramsPath(), paramsBuf, 0o644); err != nil {
		return nil, fmt.Errorf("Writing %s: %w", h.paramsPath(), err)
	}

	unlock = false
	return &h, nil
}
