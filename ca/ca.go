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
	Issuer mtc.RelativeOID

	// ServerPrefix is the URL at which the CA can be reached excluding the
	// implied "https://". For example, if the server prefix is
	// "ca.example.com/path", then the issuance endpoint is
	// "https://ca.example.com/path/ca/queue".
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

	// Mutable covered by b.mux
	signer mtc.Signer
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
	case mtc.EmptyEvidencePolicy, mtc.UmbilicalEvidencePolicy:
	case mtc.UnsetEvidencePolicy:
		return nil, errors.New("evidence policy unset")
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

	// Figure out what the next batch with assertions is likely going to be.
	existingBatches, err := h.b.ListBatchRange()
	if err != nil {
		return fmt.Errorf("listing existing batches: %w", err)
	}

	nextBatchNumber := existingBatches.End // first unissued batch
	if existingBatches.Len() == 0 {
		nextBatchNumber = 0
	}

	// If CA is lagging, the first few batches issued will be empty: take
	// the last active batch instead.
	activeBatches := h.b.Params.ActiveBatches(time.Now())
	if activeBatches.Contains(nextBatchNumber) {
		nextBatchNumber = activeBatches.End - 1
	}

	nextBatch := mtc.Batch{
		Number: nextBatchNumber,
		CA:     &h.b.Params,
	}

	batchStart, batchEnd := nextBatch.ValidityInterval()
	notAfter := make([]time.Time, len(ars)) // Corrected notAfter time.

	// We release the lock so that the potentially slow revocation checks
	// don't block the whole CA. First copy the info we need from the Handle.
	evidencePolicy := h.b.Params.EvidencePolicy
	revChecker, err := h.getRevocationChecker()
	if err != nil {
		return err
	}
	umbRoots, err := h.b.GetUmbilicalRoots()
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
		case mtc.UnsetEvidencePolicy:
			return errors.New("No evidence policy set")
		case mtc.EmptyEvidencePolicy:
		case mtc.UmbilicalEvidencePolicy:
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

			_, err = umbilical.CheckClaimsValidForX509(
				ar.Assertion.Claims,
				ar.Assertion.Subject.Abridge(),
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

// Returns a revocation checker.
//
// Requires write lock on b.mux.
func (h *Handle) getRevocationChecker() (*revocation.Checker, error) {
	if h.b.Params.EvidencePolicy != mtc.UmbilicalEvidencePolicy {
		return nil, nil
	}

	if h.revocationChecker != nil {
		return h.revocationChecker, nil
	}

	revocationChecker, err := revocation.NewChecker(revocation.Config{
		Cache: h.revocationCachePath(),
	})
	if err != nil {
		return nil, fmt.Errorf(
			"creating revocation checker from %s: %w",
			h.revocationCachePath(),
			err,
		)
	}

	h.revocationChecker = revocationChecker

	return h.revocationChecker, nil
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
		"validity-window",
		"entries",
		"evidence",
		"index",
	}
	if h.b.Params.EvidencePolicy == mtc.UmbilicalEvidencePolicy {
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
		prevHeads = h.b.Params.PreEpochTreeHeads()
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

	// Read queue and write batch entries and evidence
	besPath := gopath.Join(dir, "entries")
	besW, err := os.Create(besPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", besPath, err)
	}
	defer besW.Close()
	besBW := bufio.NewWriter(besW)

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
	if h.b.Params.EvidencePolicy == mtc.UmbilicalEvidencePolicy {
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

	// Prepare index builder
	indexPath := gopath.Join(dir, "index")
	indexW, err := os.Create(indexPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", indexPath, err)
	}

	defer indexW.Close()
	ib := internal.NewIndexBuilder(indexW)

	// Prepare tree builder
	tb := batch.NewTreeBuilder()

	if !empty {
		entryOffset := 0
		evidenceOffset := 0
		var entryKey [mtc.HashLen]byte

		err = h.walkQueue(func(ar mtc.AssertionRequest) error {
			oldEvidenceOffset := evidenceOffset
			oldEntryOffset := entryOffset

			batchStart, batchEnd := batch.ValidityInterval()

			// Skip assertions that are already expired.
			if ar.NotAfter.Before(batchStart) {
				return nil
			}

			if ar.NotAfter.After(batchEnd) {
				slog.Warn(
					"queued AssertionRequest with not_after after batch end",
					"checksum", ar.Checksum,
					"batchEnd", batchEnd,
					"notAfter", ar.NotAfter,
				)
				ar.NotAfter = batchEnd
			}

			be := mtc.NewBatchEntry(ar.Assertion, ar.NotAfter)
			if err := be.Key(entryKey[:]); err != nil {
				return fmt.Errorf("Computing key for %x: %w", ar.Checksum, err)
			}

			buf, err := be.MarshalBinary()
			if err != nil {
				return fmt.Errorf("Marshalling assertion %x: %w", ar.Checksum, err)
			}

			// Write out BatchEntry
			_, err = besBW.Write(buf)
			if err != nil {
				return fmt.Errorf(
					"Writing assertion %x to %s: %w",
					ar.Checksum,
					besPath,
					err,
				)
			}
			entryOffset += len(buf)

			// Prepare evidence when applicable: for instance by  deduplicating
			// intermediates in umbilical chains.
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

			// Write out Evidence
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
			evidenceOffset += len(buf)

			// Feed entry to tree builder, and entry and evidence to
			// index builder.
			if err := tb.Push(&be); err != nil {
				return fmt.Errorf("Building tree: %w", err)
			}

			if err := ib.Push(internal.IndexBuildEntry{
				EvidenceOffset: uint64(oldEvidenceOffset),
				Offset:         uint64(oldEntryOffset),
				Key:            entryKey,
			}); err != nil {
				return fmt.Errorf("Building index: %w", err)
			}

			return nil
		})
		if err != nil {
			return fmt.Errorf("walking queue: %w", err)
		}
	}

	err = besBW.Flush()
	if err != nil {
		return fmt.Errorf("flushing %s: %w", besPath, err)
	}

	err = besW.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", besPath, err)
	}

	err = evBW.Flush()
	if err != nil {
		return fmt.Errorf("flushing %s: %w", evPath, err)
	}

	err = evW.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", evPath, err)
	}

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
	tree, err := tb.Finish()
	if err != nil {
		return fmt.Errorf("finishing tree: %w", err)
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
	err = ib.Finish()
	if err != nil {
		return fmt.Errorf("finishing index: %w", err)
	}

	// Sign validity window
	w, err := batch.SignValidityWindow(h.signer, prevHeads, tree.Head())
	if err != nil {
		return fmt.Errorf("signing ValidityWindow: %w", err)
	}

	buf, err := w.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marhshalling SignedValidityWindow: %w", err)
	}

	wPath := gopath.Join(dir, "validity-window")
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
	if opts.EvidencePolicy == mtc.UmbilicalEvidencePolicy {
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

	if params.EvidencePolicy == mtc.UnsetEvidencePolicy {
		params.EvidencePolicy = mtc.EmptyEvidencePolicy
	}

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
	if h.b.Params.EvidencePolicy == mtc.UmbilicalEvidencePolicy {
		if err := os.WriteFile(h.b.UmbilicalRootsPath(), opts.UmbilicalRootsPEM, 0o644); err != nil {
			return nil, fmt.Errorf("Writing %s: %w", h.b.UmbilicalRootsPath(), err)
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

// SignedValidityWindowForBatch returns the signed validity window for the
// given batch number.
func (h *Handle) SignedValidityWindowForBatch(number uint32) (
	*mtc.SignedValidityWindow, error) {
	h.b.Mux.RLock()
	defer h.b.Mux.RUnlock()

	path := gopath.Join(h.b.BatchPath(number), "validity-window")
	wBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Reading signed validity window for batch number %d: %w", number, err)
	}

	w := new(mtc.SignedValidityWindow)
	err = w.UnmarshalBinary(wBytes, &h.b.Params)
	if err != nil {
		return nil, fmt.Errorf("Verifying and parsing the signed validity window: %w", err)

	}

	return w, nil
}
