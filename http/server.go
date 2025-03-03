package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sync"
	"time"

	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/ca"
)

type Server struct {
	server *http.Server
	CA     *ca.Handle
	caPath string
	WG     sync.WaitGroup // To wait on when CA is opened
}

func NewServer(caPath string, listenAddr string) *Server {

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(path.Join(caPath, "www")))))

	ret := &Server{
		server: &http.Server{
			Handler:      mux,
			Addr:         listenAddr,
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		},
		caPath: caPath,
	}
	ret.WG.Add(1)

	mux.HandleFunc("/ca/queue", ret.handleCaQueue())
	mux.HandleFunc("/ca/cert", ret.handleCaCert())

	return ret
}

func (s *Server) ListenAndServe() error {
	var err error
	s.CA, err = ca.Open(s.caPath)
	if err != nil {
		return fmt.Errorf("failed to open CA: %w", err)
	}
	s.WG.Done()
	defer func() {
		s.CA.Close()
		s.WG.Add(1)
	}()

	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func assertionRequestFromHTTPUnchecked(r *http.Request) (*mtc.AssertionRequest, error) {
	var (
		ar mtc.AssertionRequest
	)
	switch r.Method {
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()
		err = ar.UnmarshalBinary(body)
		if err != nil {
			return nil, err
		}
		return &ar, nil
	default:
		return nil, fmt.Errorf("unsupported HTTP method: %v", r.Method)
	}
}

func assertionRequestFromHTTP(r *http.Request) (*mtc.AssertionRequest, error) {
	ar, err := assertionRequestFromHTTPUnchecked(r)
	if err != nil {
		return nil, err
	}

	err = ar.Check()
	if err != nil {
		return nil, err
	}

	return ar, nil
}

func (s *Server) handleCaQueue() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := assertionRequestFromHTTP(r)
		if err != nil {
			http.Error(w, "invalid assertion", http.StatusBadRequest)
			return
		}

		err = s.CA.Queue(*a)
		if err != nil {
			http.Error(w, "failed to queue assertion", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) handleCaCert() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := assertionRequestFromHTTP(r)
		if err != nil {
			http.Error(w, "invalid assertion", http.StatusBadRequest)
			return
		}

		cert, err := s.CA.CertificateFor(a.Assertion)
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
