package mirror

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	gopath "path"
	"strings"
	"time"

	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/internal"
)

type NewOpts struct {
	ServerPrefix string
}

type Handle struct {
	b internal.Handle
}

// GET file at url and store in given file.
func getAndStore(url, filename string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf(
			"GET %s: non-200 status code: %d",
			url, resp.StatusCode,
		)
	}

	w, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create(%s): %w", filename, err)
	}
	defer w.Close()

	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("Downloading %s -> %s: %w", url, filename, err)
	}

	return nil
}

func get(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(
			"GET %s: non-200 status code: %d",
			url, resp.StatusCode,
		)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}

	return body, err
}

func getUrl(serverPrefix, path string) string {
	scheme := "https"
	if serverPrefix == "localhost" ||
		strings.HasPrefix(serverPrefix, "localhost:") ||
		strings.HasPrefix(serverPrefix, "localhost/") {
		scheme = "http"
	}

	return scheme + "://" + serverPrefix + "/mtc/v1/" + path
}

// New creates a new mirror for the Merkle Tree CA at NewOpts.ServerPrefix.
//
// Call Handle.Close() when done.
func New(path string, opts NewOpts) (*Handle, error) {
	var (
		h      Handle
		params mtc.CAParams
	)

	// Fetch ca-params
	paramsURL := getUrl(opts.ServerPrefix, "ca-params")
	paramsBuf, err := get(paramsURL)
	if err != nil {
		return nil, err
	}
	if err := params.UnmarshalBinary(paramsBuf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", paramsURL, err)
	}

	if params.ServerPrefix != opts.ServerPrefix {
		return nil, fmt.Errorf(
			"inconsistent server_prefix: %s (ca-params) ≠ %s (provided)",
			params.ServerPrefix,
			opts.ServerPrefix,
		)
	}

	// Set up basic file structure and write out params to disk
	if err := h.b.New(path, params); err != nil {
		return nil, err
	}

	unlock := true
	defer func() {
		if unlock {
			_ = h.b.FLock.Unlock()
		}
	}()

	unlock = false
	return &h, nil
}

// Load mirror state and attain file lock.
//
// Call Handle.Close() when done.
func Open(path string) (*Handle, error) {
	var h Handle
	if err := h.b.Open(path); err != nil {
		return nil, err
	}

	return &h, nil
}

// Update mirror
func (h *Handle) Update() error {
	dt := time.Now()

	// Fetch latest signed validity window
	h.b.Mux.Lock()
	defer h.b.Mux.Unlock()

	buf, err := get(h.url("batches/latest/signed-validity-window"))
	if err != nil {
		return fmt.Errorf("Fetching latest signed-validity-window: %w", err)
	}

	// Note this will also check the signature
	var svw mtc.SignedValidityWindow
	if err := svw.UnmarshalBinary(buf, &h.b.Params); err != nil {
		return fmt.Errorf("Parsing signed-validity-window: %w", err)
	}

	latestBatch := int64(svw.ValidityWindow.BatchNumber)
	mirroredBatches, err := h.b.ListBatchRange()
	if err != nil {
		return fmt.Errorf("listing existing batches: %w", err)
	}

	expectedStored := h.b.Params.StoredBatches(dt)
	expectedActive := h.b.Params.ActiveBatches(dt)

	slog.Info(
		"Current state",
		"expectedStoredRemote", expectedStored,
		"expectedActiveRemote", expectedActive,
		"latestRemoteBatch", latestBatch,
		"mirroredBatches", mirroredBatches,
	)

	latestMirroredBatch := int64(mirroredBatches.End) - 1
	if mirroredBatches.Len() == 0 {
		latestMirroredBatch = -1
	}

	logNextUpdateInfo := func() {
		if int64(expectedActive.End)-1 == latestBatch {
			slog.Info(fmt.Sprintf(
				"Next batch at the earliest in %s",
				h.b.Params.NextBatchAt(dt).Sub(dt).Truncate(time.Second),
			))
		} else if int64(expectedActive.End)-2 == latestBatch {
			notBefore, _ := (&mtc.Batch{
				Number: uint32(latestBatch + 1),
				CA:     &h.b.Params,
			}).ValidityInterval()
			slog.Info(fmt.Sprintf(
				"Next batch expected before %s",
				notBefore.Sub(dt).Truncate(time.Second),
			))
		} else {
			slog.Warn(fmt.Sprintf(
				"Remote is lagging %d batch(es) behind schedule",
				int64(expectedActive.End)-latestBatch-2,
			))
		}
	}

	if latestMirroredBatch == latestBatch {
		slog.Info("Mirror already up-to-date")
		logNextUpdateInfo()
		return nil
	}

	if latestMirroredBatch > latestBatch {
		return fmt.Errorf(
			"Latest mirrored batch is %d, whereas remote latest batch is %d",
			latestMirroredBatch,
			latestBatch,
		)
	}

	if latestBatch >= int64(expectedActive.End) {
		notBefore, _ := (&mtc.Batch{
			Number: uint32(latestBatch),
			CA:     &h.b.Params,
		}).ValidityInterval()
		return fmt.Errorf(
			"Remote's latest batch (%d) published too early: expected at %s",
			latestBatch,
			notBefore,
		)
	}

	for number := latestMirroredBatch + 1; number <= latestBatch; number++ {
		if err := h.fetchBatch(uint32(number)); err != nil {
			return fmt.Errorf("fetching batch %d: %w", number, err)
		}
	}

	logNextUpdateInfo()

	return nil
}

func (h *Handle) fetchBatch(number uint32) error {
	slog.Info("Fetching", "batch", number)

	batch := &mtc.Batch{
		Number: number,
		CA:     &h.b.Params,
	}

	// We write the batch into a temporary directory until it's all
	// checked out.
	deleteDir := true
	dir, err := os.MkdirTemp(h.b.TmpPath(), fmt.Sprintf("fetch-%d-*", number))
	if err != nil {
		return fmt.Errorf("creating temporary directory: %w", err)
	}

	defer func() {
		// TODO Should we keep the folder around for investigation?
		if deleteDir {
			os.RemoveAll(dir)
		}
	}()

	// Fetch abridged-assertions, signed-validity-window, evidence, and
	// if applicable umbilical-certificates. The rest we recompute.
	aasPath := gopath.Join(dir, "abridged-assertions")
	svwPath := gopath.Join(dir, "signed-validity-window")
	evPath := gopath.Join(dir, "evidence")

	prefix := fmt.Sprintf("batches/%d/", number)

	if err := getAndStore(
		h.url(prefix+"abridged-assertions"),
		aasPath,
	); err != nil {
		return err
	}

	svwBuf, err := get(h.url(prefix + "signed-validity-window"))
	if err != nil {
		return err
	}

	if err := os.WriteFile(svwPath, svwBuf, 0o666); err != nil {
		return fmt.Errorf("writing %s: %w", svwPath, err)
	}

	if err := getAndStore(
		h.url(prefix+"evidence"),
		evPath,
	); err != nil {
		return err
	}

	// TODO umbilical certificates

	var svw mtc.SignedValidityWindow
	if err := svw.UnmarshalBinary(svwBuf, &h.b.Params); err != nil {
		return fmt.Errorf("parsing signed-validity-window: %w", err)
	}

	// Recompute tree
	aasR, err := os.OpenFile(aasPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("opening %s: %w", aasPath, err)
	}
	defer aasR.Close()

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

	if _, err := tree.WriteTo(treeW); err != nil {
		return fmt.Errorf("writing out %s: %w", treePath, err)
	}

	// Check consistency
	if svw.ValidityWindow.BatchNumber != number {
		return fmt.Errorf(
			"remote signed-validity-window is for batch %d",
			svw.ValidityWindow.BatchNumber,
		)
	}

	var prevHeads []byte
	if number == 0 {
		prevHeads = h.b.Params.PreEpochRoots()
	} else {
		prevSVW, err := h.b.GetSignedValidityWindow(number - 1)
		if err != nil {
			return fmt.Errorf(
				"Loading signed-validity-window of batch %d: %w",
				number-1,
				err,
			)
		}

		prevHeads = prevSVW.ValidityWindow.TreeHeads
	}

	// Check whether recomputed root matches the signed validity window.
	// This is also covered by the consistency check with the previous
	// batches' roots, but checking separately will givea more helpful
	// error message.
	if !bytes.Equal(tree.Root(), svw.ValidityWindow.Root()) {
		return fmt.Errorf(
			"Root of recomputed tree (%x) does not "+
				"match root in signed-validity-window (%x)",
			tree.Root(),
			svw.ValidityWindow.Root(),
		)
	}

	heads, err := h.b.Params.NewTreeHeads(prevHeads, tree.Root())
	if err != nil {
		return fmt.Errorf("Computing expected tree heads: %w", err)
	}

	if !bytes.Equal(heads, svw.TreeHeads) {
		return fmt.Errorf(
			"TreeHeads of this batchare not consistent with the previous batch:"+
				"%x ≠ %x",
			heads,
			svw.TreeHeads,
		)
	}

	// TODO check evidence
	// TODO do we care about creating an index?

	h.b.BatchNumbersCache = nil // Invalidate cache of existing batches

	// We're all set: move temporary directory into place
	if err := os.Rename(dir, h.b.BatchPath(number)); err != nil {
		return fmt.Errorf("renaming batch dir: %w", err)
	}
	deleteDir = false

	if err = h.b.UpdateLatest(number); err != nil {
		return fmt.Errorf("Updating latest symlink: %w", err)
	}

	return nil
}

func (h *Handle) url(path string) string {
	return getUrl(h.b.Params.ServerPrefix, path)
}

func (h *Handle) Close() error {
	return h.b.Close()
}
