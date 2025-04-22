package mirror

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"errors"
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
	"github.com/bwesterb/mtc/umbilical"
	"github.com/bwesterb/mtc/umbilical/frozencas"
)

type NewOpts struct {
	ServerPrefix string

	// Fields below are optional

	// Errors if the CA doesn't have the given evidence policy.
	ExpectedEvidencePolicy mtc.EvidencePolicyType

	// Lists of accepted roots for umbilical chains. If unset, we'll fetch
	// the roots advertised by the CA itself.
	UmbilicalRootsPEM []byte
}

type Handle struct {
	b internal.Handle
}

// GET file at url and store in given file.
func getAndStore(url, filename string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
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
		return nil, err
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

	if opts.ExpectedEvidencePolicy != mtc.UnsetEvidencePolicy &&
		opts.ExpectedEvidencePolicy != params.EvidencePolicy {
		return nil, fmt.Errorf(
			"expected evidence policy %d; got %d",
			opts.ExpectedEvidencePolicy,
			params.EvidencePolicy,
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

	if params.EvidencePolicy == mtc.UmbilicalEvidencePolicy {
		umbRoots := opts.UmbilicalRootsPEM

		if umbRoots == nil {
			slog.Warn(fmt.Sprintf(
				"You did not specify umbilical roots. Fetching from CA instead. " +
					"Do you trust them?",
			))
			umbRoots, err = get(h.url("umbilical-roots.pem"))
			if err != nil {
				return nil, err
			}
		}
		if !x509.NewCertPool().AppendCertsFromPEM(umbRoots) {
			return nil, errors.New(
				"Failed to parse umbilical roots",
			)
		}
		if err := os.WriteFile(
			h.b.UmbilicalRootsPath(),
			umbRoots,
			0o644,
		); err != nil {
			return nil, fmt.Errorf("Writing %s: %w", h.b.UmbilicalRootsPath(), err)
		}
	}

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

	buf, err := get(h.url("batches/latest/validity-window"))
	if err != nil {
		return fmt.Errorf("Fetching latest validity-window: %w", err)
	}

	// Note this will also check the signature
	var svw mtc.SignedValidityWindow
	if err := svw.UnmarshalBinary(buf, &h.b.Params); err != nil {
		return fmt.Errorf("Parsing validity-window: %w", err)
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
				Number: uint32(latestBatch + 2),
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

	batchStart, batchEnd := batch.ValidityInterval()

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

	// Fetch entries, validity-window, evidence, and
	// if applicable umbilical-certificates. The rest we recompute.
	besPath := gopath.Join(dir, "entries")
	svwPath := gopath.Join(dir, "validity-window")
	evsPath := gopath.Join(dir, "evidence")
	ucPath := gopath.Join(dir, "umbilical-certificates")

	prefix := fmt.Sprintf("batches/%d/", number)

	if err := getAndStore(
		h.url(prefix+"entries"),
		besPath,
	); err != nil {
		return err
	}

	svwBuf, err := get(h.url(prefix + "validity-window"))
	if err != nil {
		return err
	}

	if err := os.WriteFile(svwPath, svwBuf, 0o666); err != nil {
		return fmt.Errorf("writing %s: %w", svwPath, err)
	}

	if err := getAndStore(
		h.url(prefix+"evidence"),
		evsPath,
	); err != nil {
		return err
	}

	var (
		ucs      []*frozencas.Handle
		umbRoots *x509.CertPool
	)
	if h.b.Params.EvidencePolicy == mtc.UmbilicalEvidencePolicy {
		umbRoots, err = h.b.GetUmbilicalRoots()
		if err != nil {
			return err
		}

		if err := getAndStore(
			h.url(prefix+"umbilical-certificates"),
			ucPath,
		); err != nil {
			return err
		}

		newUc, err := frozencas.Open(ucPath)
		if err != nil {
			return fmt.Errorf("failed to open umbilical-certificates: %w", err)
		}
		defer newUc.Close()
		ucs = append(ucs, newUc)

		// Oldest batch to inspect for deduplicated umbilical certificate
		end := int64(batch.Number) - int64(h.b.Params.ValidityWindowSize)
		if end < 0 {
			end = 0
		}

		for bn := int64(batch.Number) - 1; bn >= end; bn-- {
			uc, err := h.b.UCFor(uint32(bn))
			if err != nil {
				return fmt.Errorf(
					"opening umbilical certificates for batch %d: %w",
					bn,
					err,
				)
			}

			ucs = append(ucs, uc)
		}
	}

	var svw mtc.SignedValidityWindow
	if err := svw.UnmarshalBinary(svwBuf, &h.b.Params); err != nil {
		return fmt.Errorf("parsing validity-window: %w", err)
	}

	// Prepare to recompute tree and check evidence
	tb := batch.NewTreeBuilder()

	besR, err := os.OpenFile(besPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("opening %s: %w", besPath, err)
	}
	defer besR.Close()

	evsR, err := os.OpenFile(evsPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("opening %s: %w", evsPath, err)
	}
	defer evsR.Close()

	besC := mtc.UnmarshalBatchEntries(bufio.NewReader(besR))
	defer besC.Close()

	evsC := mtc.UnmarshalEvidenceLists(bufio.NewReader(evsR))
	defer evsC.Close()

	var (
		be  mtc.BatchEntry
		evs mtc.EvidenceList
	)

	for entryNumber := 0; ; entryNumber++ {
		err1 := besC.Pull(&be)
		err2 := evsC.Pull(&evs)
		if err1 == mtc.EOF && err1 == err2 {
			break
		}
		if err1 != nil {
			return fmt.Errorf("reading %s: %w", besPath, err1)
		}
		if err2 != nil {
			return fmt.Errorf("reading %s: %w", evsPath, err2)
		}

		if err := tb.Push(&be); err != nil {
			return fmt.Errorf("building tree: %w", err)
		}

		// TODO Would the spec allow a NotAfter before batchStart?
		//		What about not_after = batchStart?
		if be.NotAfter.After(batchEnd) || be.NotAfter.Before(batchStart) {
			return fmt.Errorf(
				"entry %d has not_after %s out of range [%s, %s]",
				entryNumber,
				be.NotAfter.UTC(),
				batchStart.UTC(),
				batchEnd.UTC(),
			)
		}

		if h.b.Params.EvidencePolicy != mtc.UmbilicalEvidencePolicy {
			continue
		}

		// Reconstruct umbilical chain
		var chain []*x509.Certificate
		for _, ev := range evs {
			switch ev.Type() {
			case mtc.UmbilicalEvidenceType:
				chain, err = ev.(mtc.UmbilicalEvidence).Chain()
				if err != nil {
					return fmt.Errorf(
						"parsing umbilical chain #%d: %w",
						entryNumber,
						err,
					)
				}
				break
			case mtc.CompressedUmbilicalEvidenceType:
				hashes := ev.(mtc.CompressedUmbilicalEvidence).Chain()
				for _, hash := range hashes {
					var rawCert []byte
					for _, uc := range ucs {
						rawCert, err = uc.Get(hash[:])
						if err != nil {
							return err
						}
						if rawCert != nil {
							break
						}
					}

					if rawCert == nil {
						return fmt.Errorf(
							"Could not find umbilical certificate for entry %d with hash %x",
							entryNumber,
							hash,
						)
					}

					cert, err := x509.ParseCertificate(rawCert)
					if err != nil {
						return fmt.Errorf(
							"Could not parse umbilical certificate for entry %d with hash %x",
							entryNumber,
							hash,
						)
					}

					chain = append(chain, cert)
				}
				break
			default:
				continue
			}
		}

		if chain == nil {
			return fmt.Errorf("No umbilical chain present for entry %d", entryNumber)
		}

		if len(chain) == 0 {
			return fmt.Errorf("Umbilical chain empty for entry %d", entryNumber)
		}

		_, err = umbilical.CheckClaimsValidForX509(
			be.Claims,
			be.Subject,
			batchStart,
			be.NotAfter,
			chain,
			umbRoots,
			nil,
		)
		if err != nil {
			return fmt.Errorf(
				"Checking umbilical chain for entry %d: %w",
				entryNumber,
				err,
			)
		}
	}

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

	if _, err := tree.WriteTo(treeW); err != nil {
		return fmt.Errorf("writing out %s: %w", treePath, err)
	}

	// Check consistency
	if svw.ValidityWindow.BatchNumber != number {
		return fmt.Errorf(
			"remote validity-window is for batch %d",
			svw.ValidityWindow.BatchNumber,
		)
	}

	var prevHeads []byte
	if number == 0 {
		prevHeads = h.b.Params.PreEpochTreeHeads()
	} else {
		prevSVW, err := h.b.GetSignedValidityWindow(number - 1)
		if err != nil {
			return fmt.Errorf(
				"Loading validity-window of batch %d: %w",
				number-1,
				err,
			)
		}

		prevHeads = prevSVW.ValidityWindow.TreeHeads
	}

	// Check whether recomputed root matches the signed validity window.
	// This is also covered by the consistency check with the previous
	// batches' roots, but checking separately will give a more helpful
	// error message.
	if !bytes.Equal(tree.Head(), svw.ValidityWindow.CurHead()) {
		return fmt.Errorf(
			"Head of recomputed tree (%x) does not "+
				"match current head in validity-window (%x)",
			tree.Head(),
			svw.ValidityWindow.CurHead(),
		)
	}

	heads, err := h.b.Params.NewTreeHeads(prevHeads, tree.Head())
	if err != nil {
		return fmt.Errorf("Computing expected tree heads: %w", err)
	}

	if !bytes.Equal(heads, svw.TreeHeads) {
		return fmt.Errorf(
			"TreeHeads of this batch are not consistent with the previous batch:"+
				"%x ≠ %x",
			heads,
			svw.TreeHeads,
		)
	}

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
