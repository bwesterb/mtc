package internal

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	gopath "path"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/nightlyone/lockfile"

	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/umbilical/frozencas"
)

var (
	ErrClosed       = errors.New("Handle is closed")
	ErrShortCircuit = errors.New("short circuit")
)

// Common functionality shared between the state of a Merkle Tree CA
// and a mirror.
type Handle struct {
	// Immutable
	Params mtc.CAParams
	Path   string

	// Mutable covered by RWLock mux
	Mux    sync.RWMutex
	FLock  lockfile.Lockfile
	Closed bool

	// Caches. Access requires either write lock on mux, or a read lock on mux
	// and a lock on cacheMux.
	CacheMux          sync.Mutex
	Indices           map[uint32]*Index            // index files
	AAs               map[uint32]*os.File          // abridged-assertions files
	EVs               map[uint32]*os.File          // evidence files
	Trees             map[uint32]*Tree             // tree files
	UCs               map[uint32]*frozencas.Handle // umbilical-certificates
	BatchNumbersCache []uint32                     // cache for existing batches
}

func (h *Handle) Close() error {
	h.Mux.Lock()
	defer h.Mux.Unlock()

	if h.Closed {
		return ErrClosed
	}

	for _, idx := range h.Indices {
		idx.Close()
	}

	for _, r := range h.AAs {
		r.Close()
	}

	for _, r := range h.EVs {
		r.Close()
	}

	for _, t := range h.Trees {
		t.Close()
	}

	for _, r := range h.UCs {
		r.Close()
	}

	h.Closed = true
	return h.FLock.Unlock()
}

func (h *Handle) TreePath(number uint32) string {
	return gopath.Join(h.BatchPath(number), "tree")
}

func (h *Handle) IndexPath(number uint32) string {
	return gopath.Join(h.BatchPath(number), "index")
}

func (h *Handle) UCPath(number uint32) string {
	return gopath.Join(h.BatchPath(number), "umbilical-certificates")
}

func (h *Handle) AAPath(number uint32) string {
	return gopath.Join(h.BatchPath(number), "abridged-assertions")
}

func (h *Handle) EVPath(number uint32) string {
	return gopath.Join(h.BatchPath(number), "evidence")
}

func (h *Handle) BatchPath(number uint32) string {
	return gopath.Join(h.BatchesPath(), fmt.Sprintf("%d", number))
}

func (h *Handle) LatestBatchPath() string {
	return gopath.Join(h.BatchesPath(), "latest")
}

func (h *Handle) BatchesPath() string {
	return gopath.Join(h.Path, "www", "mtc", "v1", "batches")
}

func (h *Handle) TmpPath() string {
	return gopath.Join(h.Path, "tmp")
}

func (h *Handle) ParamsPath() string {
	return gopath.Join(h.Path, "www", "mtc", "v1", "ca-params")
}

func (h *Handle) LockFolder() error {
	lockPath := gopath.Join(h.Path, "lock")
	absLockPath, err := filepath.Abs(lockPath)
	if err != nil {
		return fmt.Errorf("filepath.Abs(%s): %w", lockPath, err)
	}
	flock, err := lockfile.New(absLockPath)
	if err != nil {
		return fmt.Errorf("Creating lock %s: %w", absLockPath, err)
	}
	h.FLock = flock
	if err := flock.TryLock(); err != nil {
		return fmt.Errorf("Acquiring lock %s: %w", absLockPath, err)
	}
	return nil
}

func (h *Handle) GetSignedValidityWindow(number uint32) (
	*mtc.SignedValidityWindow, error) {
	var w mtc.SignedValidityWindow

	buf, err := os.ReadFile(
		gopath.Join(h.BatchPath(number), "signed-validity-window"),
	)
	if err != nil {
		return nil, err
	}

	err = w.UnmarshalBinary(buf, &h.Params)
	if err != nil {
		return nil, err
	}

	return &w, nil
}

// Returns a sorted list of batches for which a directory was created.
func (h *Handle) listBatchNumbers() ([]uint32, error) {
	h.CacheMux.Lock()
	defer h.CacheMux.Unlock()

	if h.BatchNumbersCache != nil {
		return h.BatchNumbersCache, nil
	}

	ds, err := os.ReadDir(h.BatchesPath())
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

	h.BatchNumbersCache = ret

	return ret, nil
}

// Returns range of batches for which a directory was created.
func (h *Handle) ListBatchRange() (mtc.BatchRange, error) {
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

// Returns the certificate for an issued assertion
func (h *Handle) CertificateFor(a mtc.Assertion) (*mtc.BikeshedCertificate, error) {
	h.Mux.RLock()
	defer h.Mux.RUnlock()

	aa := a.Abridge()
	var key [mtc.HashLen]byte
	err := aa.Key(key[:])
	if err != nil {
		return nil, err
	}
	res, err := h.aaByKey(key[:])
	if err != nil {
		return nil, fmt.Errorf("searching by key: %w", err)
	}

	if res == nil {
		return nil, fmt.Errorf("no assertion with key %x on record", key)
	}

	// Double-check that the assertion is present at the expected
	// offset in the abridged-assertions file.
	var key2 [mtc.HashLen]byte
	aaFile, err := h.AAFileFor(res.Batch)
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
		return ErrShortCircuit
	})
	if err != ErrShortCircuit {
		return nil, err
	}
	if !bytes.Equal(key[:], key2[:]) {
		return nil, fmt.Errorf("unable to find key %x in abridged-assertions", key)
	}

	tree, err := h.TreeFor(res.Batch)
	if err != nil {
		return nil, err
	}

	path, err := tree.AuthenticationPath(res.SequenceNumber)
	if err != nil {
		return nil, fmt.Errorf("creating authentication path: %w", err)
	}

	return &mtc.BikeshedCertificate{
		Assertion: a,
		Proof: mtc.NewMerkleTreeProof(
			&mtc.Batch{CA: &h.Params, Number: res.Batch},
			res.SequenceNumber,
			path,
		),
	}, nil
}

// Returns the evidence for an issued assertion
func (h *Handle) EvidenceFor(a mtc.Assertion) (*mtc.EvidenceList, error) {
	h.Mux.RLock()
	defer h.Mux.RUnlock()

	aa := a.Abridge()
	var key [mtc.HashLen]byte
	err := aa.Key(key[:])
	if err != nil {
		return nil, err
	}
	res, err := h.aaByKey(key[:])
	if err != nil {
		return nil, fmt.Errorf("searching by key: %w", err)
	}

	if res == nil {
		return nil, fmt.Errorf("no assertion with key %x on record", key)
	}

	var el *mtc.EvidenceList
	evFile, err := h.EVFileFor(res.Batch)
	if err != nil {
		return nil, err
	}

	_, err = evFile.Seek(int64(res.EvidenceOffset), 0)
	if err != nil {
		return nil, err
	}
	err = mtc.UnmarshalEvidenceLists(evFile, func(_ int, el2 *mtc.EvidenceList) error {
		el = el2
		return ErrShortCircuit
	})
	if err != ErrShortCircuit {
		return nil, err
	}

	return el, nil
}

// Search result for aaByKey().
type keySearchResult struct {
	Batch          uint32
	SequenceNumber uint64
	Offset         uint64
	EvidenceOffset uint64
}

// Search for AbridgedAssertions's batch/seqno/offset/evidence_offset by key.
func (h *Handle) aaByKey(key []byte) (*keySearchResult, error) {
	batches, err := h.ListBatchRange()
	if err != nil {
		return nil, fmt.Errorf("listing batches: %w", err)
	}

	if batches.Len() == 0 {
		return nil, nil
	}

	for batch := batches.End - 1; batch >= batches.Begin && batch <= batches.End; batch-- {
		res, err := h.aaByKeyIn(batch, key)
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
func (h *Handle) aaByKeyIn(batch uint32, key []byte) (*IndexSearchResult, error) {
	idx, err := h.IndexFor(batch)
	if err != nil {
		return nil, err
	}

	return idx.Search(key)
}

// Returns file handle to abridged-assertions file for the given batch.
func (h *Handle) AAFileFor(batch uint32) (*os.File, error) {
	h.CacheMux.Lock()
	defer h.CacheMux.Unlock()

	if r, ok := h.AAs[batch]; ok {
		return r, nil
	}

	r, err := os.Open(h.AAPath(batch))
	if err != nil {
		return nil, err
	}

	h.AAs[batch] = r

	return r, nil
}

// Returns file handle to evidence file for the given batch.
func (h *Handle) EVFileFor(batch uint32) (*os.File, error) {
	h.CacheMux.Lock()
	defer h.CacheMux.Unlock()

	if r, ok := h.EVs[batch]; ok {
		return r, nil
	}

	r, err := os.Open(h.EVPath(batch))
	if err != nil {
		return nil, err
	}

	h.EVs[batch] = r

	return r, nil
}

// Returns the umbilical certificates file for the given batch.
func (h *Handle) UCFor(batch uint32) (*frozencas.Handle, error) {
	h.CacheMux.Lock()
	defer h.CacheMux.Unlock()

	if r, ok := h.UCs[batch]; ok {
		return r, nil
	}

	r, err := frozencas.Open(h.UCPath(batch))
	if err != nil {
		return nil, err
	}

	h.UCs[batch] = r

	return r, nil
}

// Return the Tree handle for the given batch.
func (h *Handle) TreeFor(batch uint32) (*Tree, error) {
	h.CacheMux.Lock()
	defer h.CacheMux.Unlock()

	if t, ok := h.Trees[batch]; ok {
		return t, nil
	}

	t, err := OpenTree(h.TreePath(batch))
	if err != nil {
		return nil, err
	}

	h.Trees[batch] = t

	return t, nil
}

// Returns the AbridgedAssertions index for the given batch.
func (h *Handle) IndexFor(batch uint32) (*Index, error) {
	h.CacheMux.Lock()
	defer h.CacheMux.Unlock()

	if idx, ok := h.Indices[batch]; ok {
		return idx, nil
	}

	idx, err := OpenIndex(h.IndexPath(batch))
	if err != nil {
		return nil, err
	}

	h.Indices[batch] = idx

	return idx, nil
}

func (h *Handle) Open(path string) error {
	h.Path = path
	h.Indices = make(map[uint32]*Index)
	h.AAs = make(map[uint32]*os.File)
	h.EVs = make(map[uint32]*os.File)
	h.UCs = make(map[uint32]*frozencas.Handle)
	h.Trees = make(map[uint32]*Tree)
	if err := h.LockFolder(); err != nil {
		return err
	}
	paramsBuf, err := os.ReadFile(h.ParamsPath())
	if err != nil {
		return fmt.Errorf("reading %s: %w", h.ParamsPath(), err)
	}
	if err := h.Params.UnmarshalBinary(paramsBuf); err != nil {
		return fmt.Errorf("parsing %s: %w", h.ParamsPath(), err)
	}

	return nil
}

// Close any (cached) open files for the given batch.
func (h *Handle) CloseBatch(batch uint32) error {
	if idx, ok := h.Indices[batch]; ok {
		err := idx.Close()
		if err != nil {
			return fmt.Errorf("closing index for %d: %w", batch, err)
		}
		delete(h.Indices, batch)
	}

	if r, ok := h.AAs[batch]; ok {
		err := r.Close()
		if err != nil {
			return fmt.Errorf("closing abridged-assertions for %d: %w", batch, err)
		}
		delete(h.AAs, batch)
	}

	if r, ok := h.EVs[batch]; ok {
		err := r.Close()
		if err != nil {
			return fmt.Errorf("closing evidence for %d: %w", batch, err)
		}
		delete(h.EVs, batch)
	}

	if r, ok := h.UCs[batch]; ok {
		err := r.Close()
		if err != nil {
			return fmt.Errorf("closing umbilical-certificates for %d: %w", batch, err)
		}
		delete(h.UCs, batch)
	}

	if r, ok := h.Trees[batch]; ok {
		err := r.Close()
		if err != nil {
			return fmt.Errorf("closing tree for  %d: %w", batch, err)
		}
		delete(h.Trees, batch)
	}
	return nil
}

// Set up basic directory structure for a CA or mirror
func (h *Handle) New(path string, params mtc.CAParams) error {
	h.Params = params
	h.Path = path

	if err := params.Validate(); err != nil {
		return err
	}

	// Write out. First, create directory if it doesn't exist
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		err = os.MkdirAll(path, 0o755)
		if err != nil {
			return fmt.Errorf("os.MkdirAll(%s): %w", path, err)
		}
	} else if err != nil {
		return fmt.Errorf("os.Stat(%s): %w", path, err)
	} else if !info.IsDir() {
		return fmt.Errorf("%s: not a directory", path)
	}

	// Now, attain a file lock.
	if err := h.LockFolder(); err != nil {
		return err
	}
	unlock := true
	defer func() {
		if unlock {
			_ = h.FLock.Unlock()
		}
	}()

	// Create folders
	pubPath := h.BatchesPath()
	err = os.MkdirAll(pubPath, 0o755)
	if err != nil {
		return fmt.Errorf("os.MkdirAll(%s): %w", pubPath, err)
	}

	tmpPath := h.TmpPath()
	err = os.MkdirAll(tmpPath, 0o755)
	if err != nil {
		return fmt.Errorf("os.MkdirAll(%s): %w", tmpPath, err)
	}

	paramsPath := h.ParamsPath()
	paramsBuf, err := h.Params.MarshalBinary()
	if err != nil {
		return fmt.Errorf("Marshalling params: %w", err)
	}
	if err := os.WriteFile(paramsPath, paramsBuf, 0o644); err != nil {
		return fmt.Errorf("Writing %s: %w", paramsPath, err)
	}

	unlock = false
	return nil
}

// Updates the latest symlink to point to the given batch
func (h *Handle) UpdateLatest(number uint32) error {
	dir, err := os.MkdirTemp(h.TmpPath(), fmt.Sprintf("symlink-%d-*", number))
	if err != nil {
		return fmt.Errorf("creating temporary directory: %w", err)
	}

	defer os.RemoveAll(dir)

	newLatest := gopath.Join(dir, "latest")

	err = os.Symlink(fmt.Sprintf("%d", number), newLatest)
	if err != nil {
		return err
	}

	err = os.Rename(newLatest, h.LatestBatchPath())
	if err != nil {
		return err
	}
	return nil
}
