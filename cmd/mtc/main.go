package main

import (
	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/ca"

	"github.com/urfave/cli/v2"

	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"
)

var (
	errArgs = errors.New("Wrong number of arguments")
)

func handleCaStatus(cc *cli.Context) error {
    ca, err := ca.Open(cc.String("ca-path"))
    if err != nil {
        return err
    }
    defer ca.Close()

    fmt.Printf("Hi!\n")
    return nil
}

func handleCaNew(cc *cli.Context) error {
	if cc.Args().Len() != 2 {
		cli.ShowSubcommandHelp(cc)
		return errArgs
	}
	ca, err := ca.New(
		cc.String("ca-path"),
		ca.NewOpts{
			IssuerId:   cc.Args().Get(0),
			HttpServer: cc.Args().Get(1),
		},
	)
	if err != nil {
		return err
	}
	ca.Close()
	return nil
}

// Get the data at hand to inspect for an inspect subcommand, by either
// reading it from stdin or a file
func inspectGetBuf(cc *cli.Context) ([]byte, error) {
	if cc.Args().Len() == 0 {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(cc.Args().Get(0))
}

func handleInspectCaParams(cc *cli.Context) error {
	buf, err := inspectGetBuf(cc)
	if err != nil {
		return err
	}
	var p mtc.CAParams
	err = p.UnmarshalBinary(buf)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintf(w, "issuer_id\t%s\n", p.IssuerId)
	fmt.Fprintf(w, "start_time\t%d\t%s\n", p.StartTime,
		time.Unix(int64(p.StartTime), 0))
	fmt.Fprintf(w, "batch_duration\t%d\t%s\n", p.BatchDuration,
		time.Second*time.Duration(p.BatchDuration))
	fmt.Fprintf(w, "life_time\t%d\t%s\n", p.Lifetime,
		time.Second*time.Duration(p.Lifetime))
	fmt.Fprintf(w, "validity_window_size\t%d\n", p.ValidityWindowSize)
	fmt.Fprintf(w, "http_server\t%s\n", p.HttpServer)
	w.Flush()
	return nil
}

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name: "ca",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "ca-path",
						Usage: "path to CA state",
						Value: ".",
					},
				},
				Subcommands: []*cli.Command{
					{
						Name:      "new",
						Usage:     "creates a new CA",
						Action:    handleCaNew,
						ArgsUsage: "<issuer-id> <http-server>",
					},
					{
						Name:      "status",
						Usage:     "Shows state of CA",
						Action:    handleCaStatus,
					},
				},
			},
			{
				Name: "inspect",
				Subcommands: []*cli.Command{
					{
						Name:      "ca-params",
						Usage:     "parses ca-params file",
						Action:    handleInspectCaParams,
						ArgsUsage: "[path]",
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		if err != errArgs {
			fmt.Printf("error: %v\n", err.Error())
		}
		os.Exit(1)
	}
}
