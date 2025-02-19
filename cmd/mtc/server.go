package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bwesterb/mtc/ca"
	"github.com/bwesterb/mtc/http"
	"golang.org/x/sync/errgroup"
)

type Server struct {
	path       string
	listenAddr string
}

func NewServer(path, listenAddr string) *Server {
	return &Server{
		path:       path,
		listenAddr: listenAddr,
	}
}

func (s *Server) Serve() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGQUIT, syscall.SIGTERM)
	defer cancel()

	slog.Info("Starting server", slog.Any("listenAddr", s.listenAddr))

	srv := http.NewServer(s.path, s.listenAddr)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		slog.Info("context done, preparing to exit")
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("could not gracefully close server", slog.Any("err", err))
		}
		return nil
	})

	g.Go(func() error {
		if err := srv.ListenAndServe(); err != nil {
			return fmt.Errorf("could not start server: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		if err := issuanceLoop(s.path, ctx); err != nil {
			return fmt.Errorf("could not start issuance loop: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("unexpected errgroup error: %w", err)
	}

	return nil
}

func issuanceLoop(path string, ctx context.Context) error {
	h, err := ca.Open(path)
	if err != nil {
		return err
	}
	params := h.Params()
	err = h.Issue()
	if err != nil {
		return err
	}
	h.Close()
	for {
		batchTime := params.NextBatchAt(time.Now())
		now := time.Now()
		if batchTime.After(now) {
			slog.Info("Sleeping until next batch is ready to issue", slog.Any("at", batchTime.UTC()))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Until(batchTime)):
			}
		}

		if err = issueOnce(path); err != nil {
			return err
		}
	}
}

func issueOnce(path string) error {
	h, err := ca.Open(path)
	if err != nil {
		return err
	}
	defer h.Close()
	return h.Issue()
}
