package ca

import (
	"errors"
	"fmt"
	"io"
	"bufio"
	"bytes"
	"os"
	gopath "path"
	"path/filepath"
	"crypto/sha256"
	"time"

	"github.com/bwesterb/mtc"

	"github.com/nightlyone/lockfile"
	"golang.org/x/crypto/cryptobyte"
)

const csLen = 32

var (
    ErrChecksumInvalid = errors.New("Invalid checksum")
    ErrClosed = errors.New("Handle is closed")
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

type QueuedAssertion struct {
    Checksum []byte
    Assertion mtc.Assertion
}

func (a *QueuedAssertion) UnmarshalBinary(data []byte) error {
    var (
        s cryptobyte.String = cryptobyte.String(data)
        checksum []byte
    )
	if !s.ReadBytes(&checksum, csLen) {
		return mtc.ErrTruncated
	}

    a.Checksum = make([]byte, csLen)
    copy(a.Checksum, checksum)

    checksum2 := sha256.Sum256([]byte(s))
    if !bytes.Equal(checksum2[:], checksum) {
        return ErrChecksumInvalid
    }

    if err := a.Assertion.UnmarshalBinary([]byte(s)); err != nil {
        return err
    }

	return nil
}

func (a *QueuedAssertion) MarshalBinary() ([]byte, error) {
    var b cryptobyte.Builder

    buf, err := a.Assertion.MarshalBinary()
    if err != nil {
        return nil, err
    }

    checksum2 := sha256.Sum256([]byte(buf))
    if a.Checksum == nil {
        a.Checksum = checksum2[:]
    } else if !bytes.Equal(checksum2[:], a.Checksum) {
        return nil, ErrChecksumInvalid
    }
    b.AddBytes(a.Checksum)
    b.AddBytes(buf)

    return b.Bytes()
}

func (ca *Handle) Params() mtc.CAParams {
	return ca.params
}

func (ca *Handle) Close() error {
	if ca.closed {
        return ErrClosed
	}
	ca.closed = true
	return ca.flock.Unlock()
}

// Queue assertion for publication.
//
// If checksum is not nil, makes sure assertion matches the checksum.
func (h *Handle) Queue(a mtc.Assertion, checksum []byte) error {
    if h.closed {
        return ErrClosed
    }
    qa := QueuedAssertion{
        Checksum: checksum,
        Assertion: a,
    }

    buf, err := qa.MarshalBinary()
    if err != nil {
        return err
    }

    var b cryptobyte.Builder
    b.AddUint16(uint16(len(buf)))
    prefix, _ := b.Bytes()

    w, err := os.OpenFile(h.queuePath(), os.O_APPEND|os.O_WRONLY, 0o644)
    if err != nil {
        return fmt.Errorf("opening queue: %w", err)
    }
    defer w.Close()

    _, err = w.Write(prefix)
    if err != nil {
        return fmt.Errorf("writing to queue: %w", err)
    }

    _, err = w.Write(buf)
    if err != nil {
        return fmt.Errorf("writing to queue: %w", err)
    }

    return nil
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

func (h Handle) queuePath() string {
	return gopath.Join(h.path, "queue")
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

// Calls f on each assertion queued to be published.
func (h *Handle)  WalkQueue(f func(QueuedAssertion)error)error {
    r, err := os.OpenFile(h.queuePath(), os.O_RDONLY, 0)
    if err != nil {
        return fmt.Errorf("Opening queue: %w", err)
    }
    defer r.Close()

    br := bufio.NewReader(r)

    for {
        var (
            prefix [2]byte
            aLen uint16
            qa QueuedAssertion
        )
        _, err := io.ReadFull(br, prefix[:])
        if err == io.EOF {
            break
        }
        if err != nil {
            return fmt.Errorf("Reading queue: %w", err)
        }
        s := cryptobyte.String(prefix[:])
        _ = s.ReadUint16(&aLen) 

        buf := make([]byte, int(aLen))
        _, err = io.ReadFull(br, buf)
        if err != nil {
            return fmt.Errorf("Reading queue: %w", err)
        }

        err = qa.UnmarshalBinary(buf)
        if err != nil {
            return fmt.Errorf("Parsing queue: %w", err)
        }

        err = f(qa)
        if err != nil {
            return err
        }
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
	if err := os.WriteFile(h.queuePath(), []byte{}, 0o644); err != nil {
		return nil, fmt.Errorf("Writing %s: %w", h.queuePath(), err)
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
