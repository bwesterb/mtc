package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	gopath "path"
	"syscall"
	"time"

	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/ca"
	"github.com/bwesterb/mtc/http"
	"golang.org/x/sync/errgroup"
)

func main() {
	var path, listenAddr string

	flag.StringVar(&path, "ca-path", ".", "the path to the CA state. Defaults to the current directory.")
	flag.StringVar(&listenAddr, "listen-addr", "", "the TCP address for the server to listen on, in the form 'host:port'.")
	flag.Parse()

	if listenAddr == "" {
		var p mtc.CAParams
		buf, err := os.ReadFile(gopath.Join(path, "www", "mtc", "v1", "ca-params"))
		if err != nil {
			slog.Error("failed to read ca-params", slog.Any("err", err))
			os.Exit(1)
		}
		if err := p.UnmarshalBinary(buf); err != nil {
			slog.Error("failed to unmarshal ca-params", slog.Any("err", err))
			os.Exit(1)
		}
		listenAddr = p.HttpServer
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGQUIT, syscall.SIGTERM)
	defer cancel()

	srv := http.NewServer(path, listenAddr)

	slog.Info("starting mtcd")

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
		h, err := ca.Open(path)
		if err != nil {
			slog.Error("could not start issuance loop", slog.Any("err", err))
			return nil
		}
		h.Close()
		if err := issue(path, ctx); err != nil {
			return fmt.Errorf("could not start issuance loop: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		slog.Info("unexpected errgroup error, exiting", slog.Any("err", err))
		os.Exit(1)
	}
}

func issue(path string, ctx context.Context) error {
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
			slog.Info("Sleeping until next batch", slog.Any("at", batchTime.UTC()))
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
