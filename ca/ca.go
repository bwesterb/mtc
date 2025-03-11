package ca

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	gopath "path"
	"time"

	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/internal"
	"github.com/bwesterb/mtc/umbilical"
	"github.com/bwesterb/mtc/umbilical/frozencas"
	"github.com/bwesterb/mtc/umbilical/revocation"

	"golang.org/x/crypto/cryptobyte"
)

type NewOpts struct {
	Issuer       mtc.RelativeOID
	ServerPrefix string

	// Fields below are optional.

	SignatureScheme   mtc.SignatureScheme
	BatchDuration     time.Duration
	Lifetime          time.Duration
	StorageDuration   time.Duration
	EvidencePolicy    mtc.EvidencePolicyType
	UmbilicalRootsPEM []byte
}

// Handle for exclusive access to a Merkle Tree CA state.
type Handle struct {
	b internal.Handle

	// Covered by own lock
	revocationChecker *revocation.Checker

	// Mutable covered by d.mux
	signer         mtc.Signer
	umbilicalRoots *x509.CertPool
}

// Load private state of Merkle Tree CA, and acquire lock.
//
// Call Handle.Close() when done.
func Open(path string) (*Handle, error) {
	var h Handle
	if err := h.b.Open(path); err != nil {
		return nil, err
	}

	skBuf, err := os.ReadFile(h.skPath())
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", h.skPath(), err)
	}
	info, err := os.Stat(h.skPath())
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", h.skPath(), err)
	}
	if perm := info.Mode().Perm(); perm != 0o400 {
		return nil, fmt.Errorf(
			"incorrect filemode on %s: %o ≠ 0400",
			h.skPath(),
			perm,
		)
	}
	h.signer, err = mtc.UnmarshalSigner(h.b.Params.PublicKey.Scheme(), skBuf)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", h.skPath(), err)
	}
	switch h.b.Params.EvidencePolicy {
	case mtc.EmptyEvidencePolicyType, mtc.UmbilicalEvidencePolicyType:
	default:
		return nil, fmt.Errorf(
			"unknown evidence policy: %d",
			h.b.Params.EvidencePolicy,
		)
	}
	return &h, nil
}

func (h *Handle) Params() mtc.CAParams {
	return h.b.Params
}

func (h *Handle) Close() error {
	if err := h.b.Close(); err != nil {
		return err
	}

	if h.revocationChecker != nil {
		h.revocationChecker.Close()
	}

	return nil
}

// Drops all entries from the queue
// Requires write lock on mux.
func (h *Handle) dropQueue() error {
	if h.b.Closed {
		return internal.ErrClosed
	}
	w, err := os.OpenFile(h.queuePath(), os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("truncating queue: %w", err)
	}
	err = w.Close()
	if err != nil {
		return fmt.Errorf("closing after truncation: %w", err)
	}
	return nil
}

func (h *Handle) queueMultiple(ars []mtc.AssertionRequest) error {
	h.b.Mux.Lock()
	locked := true
	defer func() {
		if locked {
			h.b.Mux.Unlock()
		}
	}()

	if h.b.Closed {
		return internal.ErrClosed
	}

	nextBatch := mtc.Batch{
		Number: h.b.Params.ActiveBatches(time.Now()).End + 1,
		CA:     &h.b.Params,
	}
	batchStart, batchEnd := nextBatch.ValidityInterval()
	notAfter := make([]time.Time, len(ars)) // Corrected notAfter time.

	// We release the lock so that the potentially slow revocation checks
	// don't block the whole CA. First copy the info we need from the Handle.
	evidencePolicy := h.b.Params.EvidencePolicy
	revChecker, umbRoots, err := h.getRevocationCheckerAndUmbilicalRoots()
	if err != nil {
		return err
	}

	h.b.Mux.Unlock()
	locked = false

	for i, ar := range ars {
		// Check that the assertion matches the checksum.
		err := ar.Check()
		if err != nil {
			return err
		}
		notAfter[i] = ar.NotAfter
		if notAfter[i].IsZero() || batchEnd.Before(notAfter[i]) {
			notAfter[i] = batchEnd
		}

		switch evidencePolicy {
		case mtc.EmptyEvidencePolicyType:
		case mtc.UmbilicalEvidencePolicyType:
			var (
				err   error
				chain []*x509.Certificate
			)
			// TODO this checks only the first matching evidence. Do we want
			// to allow multiple of the same evidence type to be submitted,
			// and should we check them all?
			for _, ev := range ar.Evidence {
				if ev.Type() != mtc.UmbilicalEvidenceType {
					continue
				}

				chain, err = ev.(mtc.UmbilicalEvidence).Chain()
				if err != nil {
					return err
				}
				break
			}
			if chain == nil {
				return errors.New("missing x509 chain evidence")
			}
			if notAfter[i].IsZero() || chain[0].NotAfter.Before(notAfter[i]) {
				notAfter[i] = chain[0].NotAfter
			}

			_, err = umbilical.CheckAssertionValidForX509(
				ar.Assertion,
				batchStart,
				notAfter[i],
				chain,
				umbRoots,
				revChecker,
			)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf(
				"unknown evidence policy: %d",
				evidencePolicy,
			)
		}
	}

	// All good. We're ready to write.
	h.b.Mux.Lock()
	locked = true

	w, err := os.OpenFile(h.queuePath(), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening queue: %w", err)
	}
	defer w.Close()
	bw := bufio.NewWriter(w)

	for i, ar := range ars {
		if notAfter[i] != ar.NotAfter {
			ar.NotAfter = notAfter[i]
			ar.Checksum = nil // Recompute the checksum.
		}

		buf, err := ar.MarshalBinary()
		if err != nil {
			return err
		}

		var b cryptobyte.Builder
		b.AddUint16(uint16(len(buf)))
		prefix, _ := b.Bytes()

		_, err = bw.Write(prefix)
		if err != nil {
			return fmt.Errorf("writing to queue: %w", err)
		}

		_, err = bw.Write(buf)
		if err != nil {
			return fmt.Errorf("writing to queue: %w", err)
		}
	}

	return bw.Flush()
}

// Queue multiple assertions for publication.
//
// For each entry, if checksum is not nil, makes sure the assertion
// matches the checksum
//
// On error some (but not necessarily all) assertions before the error
// could be queued.
func (h *Handle) QueueMultiple(
	it func(yield func(ar mtc.AssertionRequest) error) error) error {
	// We queue in batches so that we can release locks in between
	// for revocation checks.

	const batchSize = 1024

	ars := make([]mtc.AssertionRequest, 0, batchSize)
	if err := it(func(ar mtc.AssertionRequest) error {
		ars = append(ars, ar)

		if len(ars) == batchSize {
			if err := h.queueMultiple(ars); err != nil {
				return err
			}

			ars = ars[:0]
		}

		return nil
	}); err != nil {
		return err
	}

	if len(ars) == 0 {
		return nil
	}

	return h.queueMultiple(ars)
}

// Queue assertion for publication.
//
// If checksum is not nil, makes sure assertion matches the checksum.
func (h *Handle) Queue(ar mtc.AssertionRequest) error {
	return h.QueueMultiple(func(yield func(ar mtc.AssertionRequest) error) error {
		return yield(ar)
	})
}

// Returns a revocation checker and a copy of the trusted umbilical roots.
//
// Requires write lock on mux.
func (h *Handle) getRevocationCheckerAndUmbilicalRoots() (
	*revocation.Checker, *x509.CertPool, error) {
	if h.b.Params.EvidencePolicy != mtc.UmbilicalEvidencePolicyType {
		return nil, nil, nil
	}

	if h.revocationChecker != nil {
		return h.revocationChecker, h.umbilicalRoots.Clone(), nil
	}

	revocationChecker, err := revocation.NewChecker(revocation.Config{
		Cache: h.revocationCachePath(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf(
			"creating revocation checker from %s: %w",
			h.revocationCachePath(),
			err,
		)
	}
	umbilicalRoots := x509.NewCertPool()
	pemCerts, err := os.ReadFile(h.umbilicalRootsPath())
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", h.umbilicalRootsPath(), err)
	}
	// TODO use AddCertWithConstraint to deal with constrained roots:
	// https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.md#constrained-roots
	if !umbilicalRoots.AppendCertsFromPEM(pemCerts) {
		return nil, nil, fmt.Errorf("failed to append root certs")
	}

	h.revocationChecker = revocationChecker
	h.umbilicalRoots = umbilicalRoots

	return h.revocationChecker, h.umbilicalRoots, nil
}

func (h *Handle) skPath() string {
	return gopath.Join(h.b.Path, "signing.key")
}

func (h *Handle) queuePath() string {
	return gopath.Join(h.b.Path, "queue")
}

func (h *Handle) revocationCachePath() string {
	return gopath.Join(h.b.Path, "revocation-cache")
}

func (h *Handle) umbilicalRootsPath() string {
	return gopath.Join(h.b.Path, "www", "mtc", "v1", "umbilical-roots.pem")
}

// Drop batches that don't need to be stored anymore.
//
// Requires writelock on mux.
func (h *Handle) dropOldBatches(dt time.Time) error {
	expectedStored := h.b.Params.StoredBatches(dt)
	existingBatches, err := h.b.ListBatchRange()
	if err != nil {
		return fmt.Errorf("listing existing batches: %w", err)
	}

	if existingBatches.Len() == 0 {
		return nil
	}

	if expectedStored.AreAllPast(existingBatches.End - 1) {
		// It should not happen that we delete the last active batch,
		// as we issue new (empty) batches before we prune the old.
		// Just in case, we check for it. Otherwise we'd be in a state,
		// where it's more difficult to recover from.
		return fmt.Errorf("would delete all existing batches")
	}

	h.b.BatchNumbersCache = nil // Invalidate cache of existing batches

	for batch := existingBatches.Begin; batch < existingBatches.End; batch++ {
		if !expectedStored.AreAllPast(batch) {
			break
		}

		if err := h.b.CloseBatch(batch); err != nil {
			return err
		}

		slog.Info("Removing batch", "batch", batch)
		if err := os.RemoveAll(h.b.BatchPath(batch)); err != nil {
			return fmt.Errorf("Removing batch %d: %w", batch, err)
		}
	}
	return nil
}

// Issue queued assertions into new batch.
//
// Drops batches that fall outside of storage window.
func (h *Handle) Issue() error {
	h.b.Mux.Lock()
	defer h.b.Mux.Unlock()

	if h.b.Closed {
		return internal.ErrClosed
	}

	dt := time.Now()
	err := h.issue(dt)
	if err != nil {
		return err
	}
	err = h.dropOldBatches(dt)
	if err != nil {
		return fmt.Errorf("Dropping old batches: %w", err)
	}
	return nil
}

func (h *Handle) issue(dt time.Time) error {
	slog.Info("Starting issuance", "time", dt.UTC())

	expectedStored := h.b.Params.StoredBatches(dt)
	expectedActive := h.b.Params.ActiveBatches(dt)

	existingBatches, err := h.b.ListBatchRange()
	if err != nil {
		return fmt.Errorf("listing existing batches: %w", err)
	}

	slog.Info(
		"Current state",
		"expectedStored", expectedStored,
		"expectedActive", expectedActive,
		"existingBatches", existingBatches,
	)

	// Next check which empty batches we need to publish.
	toCreate := expectedStored
	if existingBatches.Len() == 0 {
		toCreate.Begin = 0
	} else {
		// Check that this isn't the case:
		//
		//   stored:        [            ]
		//   existing:          [    ]
		if existingBatches.Begin > expectedStored.Begin {
			return fmt.Errorf(
				"Missing batches %d - %d",
				expectedStored.Begin-1,
				existingBatches.Begin,
			)
		}

		if existingBatches.End > expectedStored.End {
			return fmt.Errorf(
				"Batches %d and up exist, but should not exist yet",
				expectedActive.End,
			)
		}

		toCreate.Begin = existingBatches.End
	}

	if toCreate.Len() == 0 {
		slog.Info(fmt.Sprintf(
			"No batches were ready to issue. Next batch ready in %s.",
			h.b.Params.NextBatchAt(dt).Sub(dt).Truncate(time.Second),
		))
		return nil
	}

	slog.Info("To issue", "batches", toCreate)

	for batch := toCreate.Begin; batch < toCreate.End; batch++ {
		err := h.issueBatch(batch, batch < toCreate.End-1)
		if err != nil {
			return fmt.Errorf("issuing %d: %w", batch, err)
		}
	}

	return nil
}

// Create a new batch.
//
// Assumes this is the first batch, or the previous batch exists already.
//
// If empty is true, issues an empty batch. Otherwise, drain the queue.
func (h *Handle) issueBatch(number uint32, empty bool) error {
	deleteDir1 := true

	// We perform issuance twice, and compare results.
	dir1, err := os.MkdirTemp(h.b.TmpPath(), fmt.Sprintf("batch1-%d-*", number))
	if err != nil {
		return fmt.Errorf("creating temporary directory: %w", err)
	}
	dir2, err := os.MkdirTemp(h.b.TmpPath(), fmt.Sprintf("batch2-%d-*", number))
	if err != nil {
		return fmt.Errorf("creating temporary directory: %w", err)
	}

	defer func() {
		os.RemoveAll(dir2)
		if deleteDir1 {
			os.RemoveAll(dir1)
		}
	}()

	batch := mtc.Batch{
		Number: number,
		CA:     &h.b.Params,
	}

	err = h.issueBatchTo(dir1, batch, empty)
	if err != nil {
		return err
	}

	err = h.issueBatchTo(dir2, batch, empty)
	if err != nil {
		return err
	}

	// Ok, let's compare
	toCheck := []string{
		"tree",
		"signed-validity-window",
		"abridged-assertions",
		"evidence",
		"index",
	}
	if h.b.Params.EvidencePolicy == mtc.UmbilicalEvidencePolicyType {
		toCheck = append(toCheck, "umbilical-certificates")
	}
	err = assertFilesEqual(dir1, dir2, toCheck)
	if err != nil {
		return err
	}

	h.b.BatchNumbersCache = nil // Invalidate cache of existing batches

	// We're all set: move temporary directory into place
	err = os.Rename(dir1, h.b.BatchPath(number))
	if err != nil {
		return fmt.Errorf(
			"renaming: %w",
			err,
		)
	}

	deleteDir1 = false

	if !empty {
		err = h.dropQueue()
		if err != nil {
			return fmt.Errorf("Emptying queue: %w", err)
		}
	}

	err = h.b.UpdateLatest(number)
	if err != nil {
		return fmt.Errorf("Updating latest symlink: %w", err)
	}

	return nil
}

// Checks if the contents of the file base1/file matches that
// of base2/file for each file in files.
// Return nil if they all match, and an error otherwise.
func assertFilesEqual(base1, base2 string, files []string) error {
	for _, file := range files {
		fn1 := gopath.Join(base1, file)
		fn2 := gopath.Join(base2, file)
		hash1, err := sha256File(fn1)
		if err != nil {
			return fmt.Errorf("reading %s: %w", fn1, err)
		}
		hash2, err := sha256File(fn2)
		if err != nil {
			return fmt.Errorf("reading %s: %w", fn2, err)
		}
		if !bytes.Equal(hash1, hash2) {
			return fmt.Errorf(
				"%s doesn't match between %s and %s: %x ≠ %x",
				file,
				base1,
				base2,
				hash1,
				hash2,
			)
		}
	}
	return nil
}

// Computes sha256 hash of the given file
func sha256File(path string) ([]byte, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	h := sha256.New()
	_, err = io.Copy(h, r)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (h *Handle) compressEvidence(ev mtc.Evidence, batch mtc.Batch,
	ucBuilder *frozencas.Builder) (mtc.Evidence, error) {
	uev, ok := ev.(mtc.UmbilicalEvidence)
	if !ok {
		return ev, nil
	}

	chain, err := uev.RawChain()
	if err != nil {
		return nil, err
	}

	// Oldest batch to inspect for umbilical certificate
	end := int64(batch.Number) - int64(h.b.Params.ValidityWindowSize)
	if end < 0 {
		end = 0
	}

	hasher := sha256.New()
	hashes := make([][32]byte, len(chain))
	for i, cert := range chain {
		_, _ = hasher.Write(cert)
		hasher.Sum(hashes[i][:0])
		hash := hashes[i]
		hasher.Reset()

		ok := false
		for bn := int64(batch.Number) - 1; bn >= end; bn-- {
			uc, err := h.b.UCFor(uint32(bn))
			if err != nil {
				return nil, fmt.Errorf(
					"opening umbilical certificates for batch %d: %w",
					bn,
					err,
				)
			}

			blob, err := uc.Get(hash[:])
			if err != nil {
				return nil, fmt.Errorf(
					"Looking up umbilical certificate hash in batch %d: %w",
					bn,
					err,
				)
			}

			if blob != nil {
				ok = true // found!
				break
			}
		}

		if ok {
			continue
		}

		// Umbilical certificate not logged yet.
		err = ucBuilder.Add(cert)
		if err != nil {
			return nil, fmt.Errorf(
				"Writing umbilical certificate to frozencas: %w",
				err,
			)
		}
	}

	return mtc.NewCompressedUmbilicalEvidence(hashes)
}

// Like issueBatch, but don't write out to the correct directory yet.
// Instead, write to dir. Also, don't empty the queue.
func (h *Handle) issueBatchTo(dir string, batch mtc.Batch, empty bool) error {
	// First fetch previous tree heads
	var prevHeads []byte

	if batch.Number == 0 {
		prevHeads = h.b.Params.PreEpochRoots()
	} else {
		w, err := h.b.GetSignedValidityWindow(batch.Number - 1)
		if err != nil {
			return fmt.Errorf(
				"Loading SignedValidityWindow of batch %d: %w",
				batch.Number-1,
				err,
			)
		}

		prevHeads = w.ValidityWindow.TreeHeads
	}

	// Read queue and write abridged-assertions and evidence
	aasPath := gopath.Join(dir, "abridged-assertions")
	aasW, err := os.Create(aasPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", aasPath, err)
	}
	defer aasW.Close()
	aasBW := bufio.NewWriter(aasW)

	evPath := gopath.Join(dir, "evidence")
	evW, err := os.Create(evPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", evPath, err)
	}
	defer evW.Close()
	evBW := bufio.NewWriter(evW)

	ucPath := gopath.Join(dir, "umbilical-certificates")
	var (
		ucBuilder *frozencas.Builder
		ucW       *os.File
	)
	if h.b.Params.EvidencePolicy == mtc.UmbilicalEvidencePolicyType {
		ucW, err = os.Create(ucPath)
		if err != nil {
			return fmt.Errorf("creating %s: %w", ucPath, err)
		}
		defer ucW.Close()
		ucBuilder, err = frozencas.NewBuilder(ucW)
		if err != nil {
			return fmt.Errorf("creating %s: %w", ucPath, err)
		}
	}

	if !empty {
		err = h.walkQueue(func(ar mtc.AssertionRequest) error {
			// Skip assertions that are already expired.
			if start, _ := batch.ValidityInterval(); ar.NotAfter.Before(start) {
				return nil
			}

			// TODO add not_after to abridged assertion and proof
			// https://github.com/davidben/merkle-tree-certs/pull/92
			aa := ar.Assertion.Abridge()
			buf, err := aa.MarshalBinary()
			if err != nil {
				return fmt.Errorf("Marshalling assertion %x: %w", ar.Checksum, err)
			}

			_, err = aasBW.Write(buf)
			if err != nil {
				return fmt.Errorf(
					"Writing assertion %x to %s: %w",
					ar.Checksum,
					aasPath,
					err,
				)
			}

			evs := ar.Evidence
			if ucBuilder != nil {
				for i := range len(evs) {
					evs[i], err = h.compressEvidence(evs[i], batch, ucBuilder)
					if err != nil {
						return fmt.Errorf(
							"Compressing evidence #%d for %x: %w",
							i,
							ar.Checksum,
							err,
						)
					}
				}
			}

			buf, err = evs.MarshalBinary()
			if err != nil {
				return fmt.Errorf("Marshalling evidence %x: %w", ar.Checksum, err)
			}

			_, err = evBW.Write(buf)
			if err != nil {
				return fmt.Errorf(
					"Writing evidence %x to %s: %w",
					ar.Checksum,
					evPath,
					err,
				)
			}

			return nil
		})
		if err != nil {
			return fmt.Errorf("walking queue: %w", err)
		}
	}

	err = aasBW.Flush()
	if err != nil {
		return fmt.Errorf("flushing %s: %w", aasPath, err)
	}

	err = aasW.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", aasPath, err)
	}
	aasR, err := os.OpenFile(aasPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("opening %s: %w", aasPath, err)
	}
	defer aasR.Close()

	err = evBW.Flush()
	if err != nil {
		return fmt.Errorf("flushing %s: %w", evPath, err)
	}

	err = evW.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", evPath, err)
	}
	evR, err := os.OpenFile(evPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("opening %s: %w", evPath, err)
	}
	defer evR.Close()

	if ucBuilder != nil {
		err = ucBuilder.Finish()
		if err != nil {
			return fmt.Errorf("finishing %s: %w", ucPath, err)
		}
		err = ucW.Close()
		if err != nil {
			return fmt.Errorf("closing %s: %w", ucPath, err)
		}
	}

	// Compute tree
	tree, err := batch.ComputeTree(bufio.NewReader(aasR))
	if err != nil {
		return fmt.Errorf("computing tree: %w", err)
	}

	treePath := gopath.Join(dir, "tree")
	treeW, err := os.Create(treePath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", treePath, err)
	}

	defer treeW.Close()

	_, err = tree.WriteTo(treeW)
	if err != nil {
		return fmt.Errorf("writing out %s: %w", treePath, err)
	}

	err = treeW.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", treePath, err)
	}

	// Compute index
	_, err = aasR.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("seeking %s to start: %w", aasPath, err)
	}

	indexPath := gopath.Join(dir, "index")
	indexW, err := os.Create(indexPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", indexPath, err)
	}

	defer indexW.Close()

	err = internal.ComputeIndex(aasR, evR, indexW)
	if err != nil {
		return fmt.Errorf("computing %s to start: %w", indexPath, err)
	}

	// Sign validity window
	w, err := batch.SignValidityWindow(h.signer, prevHeads, tree.Root())
	if err != nil {
		return fmt.Errorf("signing ValidityWindow: %w", err)
	}

	buf, err := w.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marhshalling SignedValidityWindow: %w", err)
	}

	wPath := gopath.Join(dir, "signed-validity-window")
	err = os.WriteFile(wPath, buf, 0o644)
	if err != nil {
		return fmt.Errorf("writing to %s: %w", wPath, err)
	}
	return nil
}

// New creates a new Merkle Tree CA, and opens it.
//
// Call Handle.Close() when done.
func New(path string, opts NewOpts) (*Handle, error) {
	var (
		h      Handle
		params mtc.CAParams
	)

	// Set defaults
	if opts.Lifetime == 0 {
		opts.Lifetime = time.Hour * 336
	}
	if opts.BatchDuration == 0 {
		opts.BatchDuration = time.Hour * 1
	}
	if opts.StorageDuration == 0 {
		opts.StorageDuration = 2 * opts.Lifetime
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
	if opts.StorageDuration.Nanoseconds()%opts.BatchDuration.Nanoseconds() != 0 {
		return nil, errors.New("StorageDuration has to be a multiple of BatchDuration")
	}
	if opts.EvidencePolicy == mtc.UmbilicalEvidencePolicyType {
		if opts.UmbilicalRootsPEM == nil {
			return nil, errors.New("UmbilicalRoots is required with the 'umbilical' evidence policy")
		}
		if !x509.NewCertPool().AppendCertsFromPEM(opts.UmbilicalRootsPEM) {
			return nil, errors.New("Failed to parse any PEM-encoded roots from UmbilicalRootsPEM")
		}
	}
	params.ValidityWindowSize = uint64(opts.Lifetime.Nanoseconds() / opts.BatchDuration.Nanoseconds())
	params.BatchDuration = uint64(opts.BatchDuration.Nanoseconds() / 1000000000)
	params.Lifetime = uint64(opts.Lifetime.Nanoseconds() / 1000000000)
	params.StorageWindowSize = uint64(opts.StorageDuration.Nanoseconds() / opts.BatchDuration.Nanoseconds())

	params.StartTime = uint64(time.Now().Unix())

	params.ServerPrefix = opts.ServerPrefix
	params.Issuer = opts.Issuer
	params.EvidencePolicy = opts.EvidencePolicy

	if opts.SignatureScheme == 0 {
		opts.SignatureScheme = mtc.TLSMLDSA87
	}

	// Generate keypair
	signer, verifier, err := mtc.GenerateSigningKeypair(opts.SignatureScheme)
	if err != nil {
		return nil, fmt.Errorf("GenerateSigningKeypair: %w", err)
	}
	params.PublicKey = verifier
	h.signer = signer

	// Create basic directory structure, write out params.
	if err := h.b.New(path, params); err != nil {
		return nil, err
	}

	unlock := true
	defer func() {
		if unlock {
			_ = h.b.FLock.Unlock()
		}
	}()

	// Write out signing key
	if err := os.WriteFile(h.skPath(), signer.Bytes(), 0o400); err != nil {
		return nil, fmt.Errorf("writing %s: %w", h.skPath(), err)
	}

	// Queue
	if err := os.WriteFile(h.queuePath(), []byte{}, 0o644); err != nil {
		return nil, fmt.Errorf("Writing %s: %w", h.queuePath(), err)
	}

	// Accepted roots
	if h.b.Params.EvidencePolicy == mtc.UmbilicalEvidencePolicyType {
		if err := os.WriteFile(h.umbilicalRootsPath(), opts.UmbilicalRootsPEM, 0o644); err != nil {
			return nil, fmt.Errorf("Writing %s: %w", h.umbilicalRootsPath(), err)
		}
	}

	unlock = false
	return &h, nil
}

// Calls f on each assertion queued to be published.
//
// Because of locked internal state, f cannot call any function on h.
func (h *Handle) WalkQueue(f func(mtc.AssertionRequest) error) error {
	h.b.Mux.RLock()
	defer h.b.Mux.RUnlock()
	return h.walkQueue(f)
}

// Same as WalkQueue, but asummes read lock on mux.
func (h *Handle) walkQueue(f func(mtc.AssertionRequest) error) error {
	r, err := os.OpenFile(h.queuePath(), os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("Opening queue: %w", err)
	}
	defer r.Close()

	br := bufio.NewReader(r)

	for {
		var (
			prefix [2]byte
			aLen   uint16
			ar     mtc.AssertionRequest
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

		err = ar.UnmarshalBinary(buf)
		if err != nil {
			return fmt.Errorf("Parsing queue: %w", err)
		}

		err = f(ar)
		if err != nil {
			return err
		}
	}

	return nil
}

// Returns the certificate for an issued assertion
func (h *Handle) CertificateFor(a mtc.Assertion) (*mtc.BikeshedCertificate, error) {
	return h.b.CertificateFor(a)
}

// Returns the evidence for an issued assertion
func (h *Handle) EvidenceFor(a mtc.Assertion) (*mtc.EvidenceList, error) {
	return h.b.EvidenceFor(a)
}
