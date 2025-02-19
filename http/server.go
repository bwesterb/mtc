package http

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"time"

	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/ca"
)

type Server struct {
	server *http.Server
}

func NewServer(caPath string, listenAddr string) *Server {

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(path.Join(caPath, "www")))))
	mux.HandleFunc("/ca/queue", handleCaQueue(caPath))
	mux.HandleFunc("/ca/cert", handleCaCert(caPath))

	return &Server{
		server: &http.Server{
			Handler:      mux,
			Addr:         listenAddr,
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}}
}

func (s *Server) ListenAndServe() error {
	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func assertionFromRequestUnchecked(r *http.Request) (*ca.QueuedAssertion, error) {

	var (
		checksum []byte
		err      error
	)

	checksumParam := r.URL.Query().Get("checksum")
	if checksumParam != "" {
		checksum, err = hex.DecodeString(checksumParam)
		if err != nil {
			return nil, err
		}
	}
	var a mtc.Assertion
	switch r.Method {
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()

		err = a.UnmarshalBinary(body)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported HTTP method: %v", r.Method)
	}

	return &ca.QueuedAssertion{
		Assertion: a,
		Checksum:  checksum,
	}, nil
}

func assertionFromRequest(r *http.Request) (*ca.QueuedAssertion, error) {
	qa, err := assertionFromRequestUnchecked(r)
	if err != nil {
		return nil, err
	}

	err = qa.Check()
	if err != nil {
		return nil, err
	}

	return qa, nil
}

func handleCaQueue(path string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		h, err := ca.Open(path)
		if err != nil {
			http.Error(w, "failed to open CA", http.StatusInternalServerError)
			return
		}
		defer h.Close()
		qa, err := assertionFromRequest(r)
		if err != nil {
			http.Error(w, "invalid assertion", http.StatusBadRequest)
			return
		}

		err = h.Queue(qa.Assertion, qa.Checksum)
		if err != nil {
			http.Error(w, "failed to queue assertion", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func handleCaCert(path string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		h, err := ca.Open(path)
		if err != nil {
			http.Error(w, "failed to open CA", http.StatusInternalServerError)
			return
		}
		defer h.Close()
		qa, err := assertionFromRequest(r)
		if err != nil {
			http.Error(w, "invalid assertion", http.StatusBadRequest)
			return
		}

		cert, err := h.CertificateFor(qa.Assertion)
		if err != nil {
			http.Error(w, "failed to get certificate for assertion", http.StatusBadRequest)
			return
		}

		buf, err := cert.MarshalBinary()
		if err != nil {
			http.Error(w, "failed to marshal certificate", http.StatusInternalServerError)
			return
		}

		_, err = w.Write(buf)
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
			return
		}
	}
}
