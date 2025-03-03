package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bwesterb/mtc/http"
	"golang.org/x/sync/errgroup"
)

type Server struct {
	srv *http.Server
}

func NewServer(path, listenAddr string) *Server {
	return &Server{
		srv: http.NewServer(path, listenAddr),
	}
}

func (s *Server) Serve() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGQUIT, syscall.SIGTERM)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		slog.Info("context done, preparing to exit")
		if err := s.srv.Shutdown(ctx); err != nil {
			slog.Error("could not gracefully close server", slog.Any("err", err))
		}
		return nil
	})

	g.Go(func() error {
		if err := s.srv.ListenAndServe(); err != nil {
			return fmt.Errorf("could not start server: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		if err := s.issuanceLoop(ctx); err != nil {
			return fmt.Errorf("could not start issuance loop: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("unexpected errgroup error: %w", err)
	}

	return nil
}

func (s *Server) issuanceLoop(ctx context.Context) error {
	s.srv.WG.Wait()
	params := s.srv.CA.Params()
	err := s.srv.CA.Issue()
	if err != nil {
		return err
	}
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

		if err = s.srv.CA.Issue(); err != nil {
			return err
		}
	}
}
