package mirror

import (
	"fmt"
	"io"
	"net/http"

	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/internal"
)

type NewOpts struct {
	ServerPrefix string
}

type Handle struct {
	b internal.Handle
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

// New creates a new mirror for the Merkle Tree CA at NewOpts.ServerPrefix.
//
// Call Handle.Close() when done.
func New(path string, opts NewOpts) (*Handle, error) {
	var (
		h      Handle
		params mtc.CAParams
	)

	// Fetch ca-params
	paramsURL := "https://" + opts.ServerPrefix + "/mtc/v1/ca-params"
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

func (h *Handle) Close() error {
	return h.b.Close()
}
