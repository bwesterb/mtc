package ca

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	gopath "path"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/bwesterb/mtc"

	"github.com/nightlyone/lockfile"
	"golang.org/x/crypto/cryptobyte"
)

var (
	ErrClosed = errors.New("Handle is closed")
)

type NewOpts struct {
	Issuer     mtc.RelativeOID
	HttpServer string

	// Fields below are optional.

	SignatureScheme mtc.SignatureScheme
	BatchDuration   time.Duration
	Lifetime        time.Duration
	StorageDuration time.Duration
}

// Handle for exclusive access to a Merkle Tree CA state.
type Handle struct {
	params mtc.CAParams
	signer mtc.Signer
	flock  lockfile.Lockfile
	path   string
	closed bool

	indices map[uint32]*Index
	aas     map[uint32]*os.File
	evs     map[uint32]*os.File
	trees   map[uint32]*Tree

	batchNumbersCache []uint32 // cache for existing batches
}

func (ca *Handle) Params() mtc.CAParams {
	return ca.params
}

func (ca *Handle) Close() error {
	if ca.closed {
		return ErrClosed
	}

	for _, idx := range ca.indices {
		idx.Close()
	}

	for _, r := range ca.aas {
		r.Close()
	}

	for _, r := range ca.evs {
		r.Close()
	}

	for _, t := range ca.trees {
		t.Close()
	}

	ca.closed = true
	return ca.flock.Unlock()
}

// Drops all entries from the queue
func (h *Handle) dropQueue() error {
	if h.closed {
		return ErrClosed
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

// Queue multiple assertions for publication.
//
// For each entry, if checksum is not nil, makes sure the assertion
// matches the checksum
func (h *Handle) QueueMultiple(it func(yield func(ar mtc.AssertionRequest) error) error) error {
	if h.closed {
		return ErrClosed
	}

	w, err := os.OpenFile(h.queuePath(), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening queue: %w", err)
	}
	defer w.Close()
	bw := bufio.NewWriter(w)

	if err := it(func(ar mtc.AssertionRequest) error {
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

		return nil
	}); err != nil {
		return err
	}

	return bw.Flush()
}

// Queue assertion for publication.
//
// If checksum is not nil, makes sure assertion matches the checksum.
func (h *Handle) Queue(ar mtc.AssertionRequest) error {
	return h.QueueMultiple(func(yield func(ar mtc.AssertionRequest) error) error {
		return yield(ar)
	})
}

// Load private state of Merkle Tree CA, and acquire lock.
//
// Call Handle.Close() when done.
func Open(path string) (*Handle, error) {
	h := Handle{
		path:    path,
		indices: make(map[uint32]*Index),
		aas:     make(map[uint32]*os.File),
		evs:     make(map[uint32]*os.File),
		trees:   make(map[uint32]*Tree),
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

func (h Handle) treePath(number uint32) string {
	return gopath.Join(h.batchPath(number), "tree")
}

func (h Handle) indexPath(number uint32) string {
	return gopath.Join(h.batchPath(number), "index")
}

func (h Handle) aaPath(number uint32) string {
	return gopath.Join(h.batchPath(number), "abridged-assertions")
}

func (h Handle) evPath(number uint32) string {
	return gopath.Join(h.batchPath(number), "evidence")
}

func (h Handle) batchPath(number uint32) string {
	return gopath.Join(h.batchesPath(), fmt.Sprintf("%d", number))
}

func (h Handle) latestBatchPath() string {
	return gopath.Join(h.batchesPath(), "latest")
}

func (h Handle) batchesPath() string {
	return gopath.Join(h.path, "www", "mtc", "v1", "batches")
}

func (h Handle) tmpPath() string {
	return gopath.Join(h.path, "tmp")
}

func (h Handle) getSignedValidityWindow(number uint32) (
	*mtc.SignedValidityWindow, error) {
	var w mtc.SignedValidityWindow

	buf, err := os.ReadFile(
		gopath.Join(h.batchPath(number), "signed-validity-window"),
	)
	if err != nil {
		return nil, err
	}

	err = w.UnmarshalBinary(buf, &h.params)
	if err != nil {
		return nil, err
	}

	return &w, nil
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

// Returns a sorted list of batches for which a directory was created.
func (h *Handle) listBatchNumbers() ([]uint32, error) {
	if h.batchNumbersCache != nil {
		return h.batchNumbersCache, nil
	}

	ds, err := os.ReadDir(h.batchesPath())
	if err != nil {
		return nil, err
	}
	ret := []uint32{}
	for _, d := range ds {
		if !d.IsDir() {
			continue
		}
		name := d.Name()
		batch, err := strconv.ParseUint(name, 10, 32)
		if err != nil {
			continue
		}
		ret = append(ret, uint32(batch))
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i] < ret[j]
	})

	h.batchNumbersCache = ret

	return ret, nil
}

// Returns range of batches for which a directory was created.
func (h *Handle) listBatchRange() (mtc.BatchRange, error) {
	var ret mtc.BatchRange
	numbers, err := h.listBatchNumbers()
	if err != nil {
		return ret, err
	}
	if len(numbers) == 0 {
		return ret, nil
	}
	begin := numbers[0]
	end := numbers[len(numbers)-1]
	if end-begin != uint32(len(numbers)-1) {
		return ret, fmt.Errorf("Missing batches")
	}
	return mtc.BatchRange{
		Begin: begin,
		End:   end + 1,
	}, nil
}

// Calls f on each assertion queued to be published.
func (h *Handle) WalkQueue(f func(mtc.AssertionRequest) error) error {
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

// Drop batches that don't need to be stored anymore.
func (h *Handle) dropOldBatches(dt time.Time) error {
	expectedStored := h.params.StoredBatches(dt)
	existingBatches, err := h.listBatchRange()
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

	h.batchNumbersCache = nil // Invalidate cache of existing batches

	for batch := existingBatches.Begin; batch < existingBatches.End; batch++ {
		if !expectedStored.AreAllPast(batch) {
			break
		}

		if err := h.closeBatch(batch); err != nil {
			return err
		}

		slog.Info("Removing batch", "batch", batch)
		if err := os.RemoveAll(h.batchPath(batch)); err != nil {
			return fmt.Errorf("Removing batch %d: %w", batch, err)
		}
	}
	return nil
}

// Close any (cached) open files for the given batch.
func (h *Handle) closeBatch(batch uint32) error {
	if idx, ok := h.indices[batch]; ok {
		err := idx.Close()
		if err != nil {
			return fmt.Errorf("closing index for %d: %w", batch, err)
		}
		delete(h.indices, batch)
	}

	if r, ok := h.aas[batch]; ok {
		err := r.Close()
		if err != nil {
			return fmt.Errorf("closing abridged-assertions for %d: %w", batch, err)
		}
		delete(h.aas, batch)
	}

	if r, ok := h.evs[batch]; ok {
		err := r.Close()
		if err != nil {
			return fmt.Errorf("closing evidence for %d: %w", batch, err)
		}
		delete(h.evs, batch)
	}

	if r, ok := h.trees[batch]; ok {
		err := r.Close()
		if err != nil {
			return fmt.Errorf("closing tree for  %d: %w", batch, err)
		}
		delete(h.trees, batch)
	}
	return nil
}

// Returns the AbridgedAssertions index for the given batch.
func (ca *Handle) indexFor(batch uint32) (*Index, error) {
	if idx, ok := ca.indices[batch]; ok {
		return idx, nil
	}

	idx, err := OpenIndex(ca.indexPath(batch))
	if err != nil {
		return nil, err
	}

	ca.indices[batch] = idx

	return idx, nil
}

// Return the Tree handle for the given batch.
func (ca *Handle) treeFor(batch uint32) (*Tree, error) {
	if t, ok := ca.trees[batch]; ok {
		return t, nil
	}

	t, err := OpenTree(ca.treePath(batch))
	if err != nil {
		return nil, err
	}

	ca.trees[batch] = t

	return t, nil
}

// Returns file handle to abridged-assertions file for the given batch.
func (ca *Handle) aaFileFor(batch uint32) (*os.File, error) {
	if r, ok := ca.aas[batch]; ok {
		return r, nil
	}

	r, err := os.Open(ca.aaPath(batch))
	if err != nil {
		return nil, err
	}

	ca.aas[batch] = r

	return r, nil
}

// Returns file handle to evidence file for the given batch.
func (ca *Handle) evFileFor(batch uint32) (*os.File, error) {
	if r, ok := ca.evs[batch]; ok {
		return r, nil
	}

	r, err := os.Open(ca.evPath(batch))
	if err != nil {
		return nil, err
	}

	ca.evs[batch] = r

	return r, nil
}

type keySearchResult struct {
	Batch          uint32
	SequenceNumber uint64
	Offset         uint64
	EvidenceOffset uint64
}

var errShortCircuit = errors.New("short circuit")

// Returns the certificate for an issued assertion
func (ca *Handle) CertificateFor(a mtc.Assertion) (*mtc.BikeshedCertificate, error) {
	aa := a.Abridge()
	var key [mtc.HashLen]byte
	err := aa.Key(key[:])
	if err != nil {
		return nil, err
	}
	res, err := ca.aaByKey(key[:])
	if err != nil {
		return nil, fmt.Errorf("searching by key: %w", err)
	}

	if res == nil {
		return nil, fmt.Errorf("no assertion with key %x on record", key)
	}

	// Double-check that the assertion is present at the expected
	// offset in the abridged-assertions file.
	var key2 [mtc.HashLen]byte
	aaFile, err := ca.aaFileFor(res.Batch)
	if err != nil {
		return nil, err
	}
	_, err = aaFile.Seek(int64(res.Offset), 0)
	if err != nil {
		return nil, err
	}
	err = mtc.UnmarshalAbridgedAssertions(aaFile, func(_ int, aa *mtc.AbridgedAssertion) error {
		err := aa.Key(key2[:])
		if err != nil {
			return err
		}
		return errShortCircuit
	})
	if err != errShortCircuit {
		return nil, err
	}
	if !bytes.Equal(key[:], key2[:]) {
		return nil, fmt.Errorf("unable to find key %x in abridged-assertions", key)
	}

	tree, err := ca.treeFor(res.Batch)
	if err != nil {
		return nil, err
	}

	path, err := tree.AuthenticationPath(res.SequenceNumber)
	if err != nil {
		return nil, fmt.Errorf("creating authentication path: %w", err)
	}

	p := ca.Params()
	return &mtc.BikeshedCertificate{
		Assertion: a,
		Proof: mtc.NewMerkleTreeProof(
			&mtc.Batch{CA: &p, Number: res.Batch},
			res.SequenceNumber,
			path,
		),
	}, nil
}

// Returns the evidence for an issued assertion
func (ca *Handle) EvidenceFor(a mtc.Assertion) (*mtc.EvidenceList, error) {
	aa := a.Abridge()
	var key [mtc.HashLen]byte
	err := aa.Key(key[:])
	if err != nil {
		return nil, err
	}
	res, err := ca.aaByKey(key[:])
	if err != nil {
		return nil, fmt.Errorf("searching by key: %w", err)
	}

	if res == nil {
		return nil, fmt.Errorf("no assertion with key %x on record", key)
	}

	var el *mtc.EvidenceList
	evFile, err := ca.evFileFor(res.Batch)
	if err != nil {
		return nil, err
	}

	_, err = evFile.Seek(int64(res.EvidenceOffset), 0)
	if err != nil {
		return nil, err
	}
	err = mtc.UnmarshalEvidenceLists(evFile, func(_ int, el2 *mtc.EvidenceList) error {
		el = el2
		return errShortCircuit
	})
	if err != errShortCircuit {
		return nil, err
	}

	return el, nil
}

// Search for AbridgedAssertions's batch/seqno/offset/evidence_offset by key.
func (ca *Handle) aaByKey(key []byte) (*keySearchResult, error) {
	batches, err := ca.listBatchRange()
	if err != nil {
		return nil, fmt.Errorf("listing batches: %w", err)
	}

	if batches.Len() == 0 {
		return nil, nil
	}

	for batch := batches.End - 1; batch >= batches.Begin && batch <= batches.End; batch-- {
		res, err := ca.aaByKeyIn(batch, key)
		if err != nil {
			return nil, fmt.Errorf("Searching in batch %d: %w", batch, err)
		}
		if res != nil {
			return &keySearchResult{
				Batch:          batch,
				SequenceNumber: res.SequenceNumber,
				Offset:         res.Offset,
				EvidenceOffset: res.EvidenceOffset,
			}, nil
		}
	}

	return nil, nil
}

// Find AbridgedAssertion's seqno/offset by key in the given batch.
func (ca *Handle) aaByKeyIn(batch uint32, key []byte) (*IndexSearchResult, error) {
	idx, err := ca.indexFor(batch)
	if err != nil {
		return nil, err
	}

	return idx.Search(key)
}

// Issue queued assertions into new batch.
//
// Drops batches that fall outside of storage window.
func (h *Handle) Issue() error {
	if h.closed {
		return ErrClosed
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

	expectedStored := h.params.StoredBatches(dt)
	expectedActive := h.params.ActiveBatches(dt)

	existingBatches, err := h.listBatchRange()
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
			h.params.NextBatchAt(dt).Sub(dt).Truncate(time.Second),
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
	dir1, err := os.MkdirTemp(h.tmpPath(), fmt.Sprintf("batch1-%d-*", number))
	if err != nil {
		return fmt.Errorf("creating temporary directory: %w", err)
	}
	dir2, err := os.MkdirTemp(h.tmpPath(), fmt.Sprintf("batch2-%d-*", number))
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
		CA:     &h.params,
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
	err = assertFilesEqual(
		dir1,
		dir2,
		[]string{
			"tree",
			"signed-validity-window",
			"abridged-assertions",
			"evidence",
			"index",
		},
	)
	if err != nil {
		return err
	}

	h.batchNumbersCache = nil // Invalidate cache of existing batches

	// We're all set: move temporary directory into place
	err = os.Rename(dir1, h.batchPath(number))
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

	err = h.updateLatest(number)
	if err != nil {
		return fmt.Errorf("Updating latest symlink: %w", err)
	}

	return nil
}

// Updates the latest symlink to point to the given batch
func (h *Handle) updateLatest(number uint32) error {
	dir, err := os.MkdirTemp(h.tmpPath(), fmt.Sprintf("symlink-%d-*", number))
	if err != nil {
		return fmt.Errorf("creating temporary directory: %w", err)
	}

	defer os.RemoveAll(dir)

	newLatest := gopath.Join(dir, "latest")

	err = os.Symlink(fmt.Sprintf("%d", number), newLatest)
	if err != nil {
		return err
	}

	err = os.Rename(newLatest, h.latestBatchPath())
	if err != nil {
		return err
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

// Like issueBatch, but don't write out to the correct directory yet.
// Instead, write to dir. Also, don't empty the queue.
func (h *Handle) issueBatchTo(dir string, batch mtc.Batch, empty bool) error {
	// First fetch previous tree heads
	var prevHeads []byte

	if batch.Number == 0 {
		prevHeads = h.params.PreEpochRoots()
	} else {
		w, err := h.getSignedValidityWindow(batch.Number - 1)
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

	if !empty {
		err = h.WalkQueue(func(ar mtc.AssertionRequest) error {
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

			ev := ar.Evidence
			buf, err = ev.MarshalBinary()
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

	err = ComputeIndex(aasR, evR, indexW)
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
	h.params.ValidityWindowSize = uint64(opts.Lifetime.Nanoseconds() / opts.BatchDuration.Nanoseconds())
	h.params.BatchDuration = uint64(opts.BatchDuration.Nanoseconds() / 1000000000)
	h.params.Lifetime = uint64(opts.Lifetime.Nanoseconds() / 1000000000)
	h.params.StorageWindowSize = uint64(opts.StorageDuration.Nanoseconds() / opts.BatchDuration.Nanoseconds())

	h.params.StartTime = uint64(time.Now().Unix())

	h.params.HttpServer = opts.HttpServer
	h.params.Issuer = opts.Issuer

	if opts.SignatureScheme == 0 {
		opts.SignatureScheme = mtc.TLSMLDSA87
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
			_ = h.flock.Unlock()
		}
	}()

	// Write out signing key
	if err := os.WriteFile(h.skPath(), signer.Bytes(), 0o400); err != nil {
		return nil, fmt.Errorf("writing %s: %w", h.skPath(), err)
	}

	// Create folders
	pubPath := h.batchesPath()
	err = os.MkdirAll(pubPath, 0o755)
	if err != nil {
		return nil, fmt.Errorf("os.MkdirAll(%s): %w", pubPath, err)
	}

	tmpPath := h.tmpPath()
	err = os.MkdirAll(tmpPath, 0o755)
	if err != nil {
		return nil, fmt.Errorf("os.MkdirAll(%s): %w", tmpPath, err)
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
