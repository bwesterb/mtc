package main

import (
	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/ca"

	"github.com/urfave/cli/v2"

	"bufio"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/pprof"
	"text/tabwriter"
	"time"
)

var (
	errArgs     = errors.New("Wrong number of arguments")
	fCpuProfile *os.File
)

func handleCaQueue(cc *cli.Context) error {
	var (
		checksum []byte
		err      error
	)
	cs := mtc.Claims{
		DNS:         cc.StringSlice("dns"),
		DNSWildcard: cc.StringSlice("dns-wildcard"),
	}

	for _, ip := range cc.StringSlice("ip4") {
		cs.IPv4 = append(cs.IPv4, net.ParseIP(ip))
	}

	for _, ip := range cc.StringSlice("ip6") {
		cs.IPv6 = append(cs.IPv6, net.ParseIP(ip))
	}

	if (cc.String("tls-pem") == "" &&
		cc.String("tls-der") == "") ||
		(cc.String("tls-pem") != "" &&
			cc.String("tls-der") != "") {
		return errors.New("Expect either tls-pem or tls-der flag")
	}

	usingPem := false
	subjectPath := cc.String("tls-der")
	if cc.String("tls-pem") != "" {
		usingPem = true
		subjectPath = cc.String("tls-pem")
	}

	subjectBuf, err := os.ReadFile(subjectPath)
	if err != nil {
		return fmt.Errorf("reading subject %s: %w", subjectPath, err)
	}

	if usingPem {
		block, _ := pem.Decode([]byte(subjectBuf))
		if block == nil {
			return fmt.Errorf(
				"reading subject %s: failed to parse PEM block",
				subjectPath,
			)
		}
		subjectBuf = block.Bytes
	}

	pub, err := x509.ParsePKIXPublicKey(subjectBuf)
	if err != nil {
		return fmt.Errorf("Parsing subject %s: %w", subjectPath, err)
	}

	var scheme mtc.SignatureScheme
	if cc.String("tls-scheme") != "" {
		scheme = mtc.SignatureSchemeFromString(cc.String("tls-scheme"))
		if scheme == 0 {
			return fmt.Errorf("Unknown TLS signature scheme: %s", scheme)
		}
	} else {
		schemes := mtc.SignatureSchemesFor(pub)
		if len(schemes) == 0 {
			return fmt.Errorf("No matching signature scheme for that public key")
		}
		if len(schemes) >= 2 {
			return fmt.Errorf("Specify --tls-scheme with one of %s", schemes)
		}
		scheme = schemes[0]
	}

	subj, err := mtc.NewTLSSubject(scheme, pub)
	if err != nil {
		return fmt.Errorf("creating subject: %w", err)
	}

	a := mtc.Assertion{
		Claims:  cs,
		Subject: subj,
	}

	if cc.String("checksum") != "" {
		checksum, err = hex.DecodeString(cc.String("checksum"))
		if err != nil {
			fmt.Errorf("Parsing checksum: %w", err)
		}
	}

	h, err := ca.Open(cc.String("ca-path"))
	if err != nil {
		return err
	}
	defer h.Close()

	return h.QueueMultiple(func(yield func(qa ca.QueuedAssertion) error) error {
		for i := 0; i < cc.Int("debug-repeat"); i++ {
			if err := yield(
				ca.QueuedAssertion{
					Assertion: a,
					Checksum:  checksum,
				},
			); err != nil {
				return err
			}
		}
		return nil
	})
}

func handleCaIssue(cc *cli.Context) error {
	h, err := ca.Open(cc.String("ca-path"))
	if err != nil {
		return err
	}
	defer h.Close()

	return h.Issue()
}

func handleCaShowQueue(cc *cli.Context) error {
	h, err := ca.Open(cc.String("ca-path"))
	if err != nil {
		return err
	}
	defer h.Close()

	count := 0

	err = h.WalkQueue(func(qa ca.QueuedAssertion) error {
		count++
		a := qa.Assertion
		cs := a.Claims
		subj := a.Subject
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
		fmt.Fprintf(w, "checksum\t%x\n", qa.Checksum)
		fmt.Fprintf(w, "subject_type\t%s\n", subj.Type())
		switch subj := subj.(type) {
		case *mtc.TLSSubject:
			asubj := subj.Abridge().(*mtc.AbridgedTLSSubject)
			fmt.Fprintf(w, "signature_scheme\t%s\n", asubj.SignatureScheme)
			fmt.Fprintf(w, "public_key_hash\t%x\n", asubj.PublicKeyHash[:])
		}
		if len(cs.DNS) != 0 {
			fmt.Fprintf(w, "dns\t%s\n", cs.DNS)
		}
		if len(cs.DNSWildcard) != 0 {
			fmt.Fprintf(w, "dns_wildcard\t%s\n", cs.DNSWildcard)
		}
		if len(cs.IPv4) != 0 {
			fmt.Fprintf(w, "ip4\t%s\n", cs.IPv4)
		}
		if len(cs.IPv6) != 0 {
			fmt.Fprintf(w, "ip6\t%s\n", cs.IPv6)
		}
		w.Flush()
		fmt.Printf("\n")
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("Total number of assertions in queue: %d\n", count)
	return nil
}

func handleCaNew(cc *cli.Context) error {
	if cc.Args().Len() != 2 {
		cli.ShowSubcommandHelp(cc)
		return errArgs
	}
	h, err := ca.New(
		cc.String("ca-path"),
		ca.NewOpts{
			IssuerId:   cc.Args().Get(0),
			HttpServer: cc.Args().Get(1),

			BatchDuration:   cc.Duration("batch-duration"),
			StorageDuration: cc.Duration("storage-duration"),
			Lifetime:        cc.Duration("lifetime"),
		},
	)
	if err != nil {
		return err
	}
	h.Close()
	return nil
}

// Get the data at hand to inspect for an inspect subcommand, by either
// reading it from stdin or a file
func inspectGetBuf(cc *cli.Context) ([]byte, error) {
	r, err := inspectGetReader(cc)
	if err != nil {
		return nil, err
	}
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	err = r.Close()
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// Same as inspectGetBuf(), but returns a io.ReadCloser instead.
func inspectGetReader(cc *cli.Context) (io.ReadCloser, error) {
	if cc.Args().Len() == 0 {
		return os.Stdin, nil
	}
	r, err := os.Open(cc.Args().Get(0))
	if err != nil {
		return nil, err
	}
	return r, nil
}

func inspectGetCAParams(cc *cli.Context) (*mtc.CAParams, error) {
	var p mtc.CAParams
	path := cc.String("ca-params")
	if path == "" {
		return nil, errors.New("missing ca-params flag")
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if err := p.UnmarshalBinary(buf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &p, nil
}

func handleInspectSignedValidityWindow(cc *cli.Context) error {
	buf, err := inspectGetBuf(cc)
	if err != nil {
		return err
	}
	p, err := inspectGetCAParams(cc)
	if err != nil {
		return err
	}

	var sw mtc.SignedValidityWindow
	err = sw.UnmarshalBinary(buf, p) // this also checks the signature
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintf(w, "signature\t✅\n")
	fmt.Fprintf(w, "batch_number\t%d\n", sw.ValidityWindow.BatchNumber)
	for i := 0; i < int(p.ValidityWindowSize); i++ {
		fmt.Fprintf(
			w,
			"tree_heads[%d]\t%x\n",
			i,
			sw.ValidityWindow.TreeHeads[mtc.HashLen*i:mtc.HashLen*(i+1)],
		)
	}

	w.Flush()
	return nil
}

func handleInspectAbridgedAssertions(cc *cli.Context) error {
	r, err := inspectGetReader(cc)
	if err != nil {
		return err
	}
	defer r.Close()

	count := 0
	err = mtc.UnmarshalAbridgedAssertions(
		bufio.NewReader(r),
		func(aa *mtc.AbridgedAssertion) error {
			count++
			cs := aa.Claims
			subj := aa.Subject
			w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
			fmt.Fprintf(w, "subject_type\t%s\n", subj.Type())
			switch subj := subj.(type) {
			case *mtc.AbridgedTLSSubject:
				fmt.Fprintf(w, "signature_scheme\t%s\n", subj.SignatureScheme)
				fmt.Fprintf(w, "public_key_hash\t%x\n", subj.PublicKeyHash[:])
			}
			if len(cs.DNS) != 0 {
				fmt.Fprintf(w, "dns\t%s\n", cs.DNS)
			}
			if len(cs.DNSWildcard) != 0 {
				fmt.Fprintf(w, "dns_wildcard\t%s\n", cs.DNSWildcard)
			}
			if len(cs.IPv4) != 0 {
				fmt.Fprintf(w, "ip4\t%s\n", cs.IPv4)
			}
			if len(cs.IPv6) != 0 {
				fmt.Fprintf(w, "ip6\t%s\n", cs.IPv6)
			}
			w.Flush()
			fmt.Printf("\n")
			return nil
		},
	)
	if err != nil {
		return err
	}
	fmt.Printf("Total number of abridged assertions: %d\n", count)
	return nil
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
	fmt.Fprintf(w, "storage_window_size\t%d\t%s\n", p.StorageWindowSize,
		time.Second*time.Duration(p.BatchDuration*p.StorageWindowSize))
	fmt.Fprintf(w, "validity_window_size\t%d\n", p.ValidityWindowSize)
	fmt.Fprintf(w, "http_server\t%s\n", p.HttpServer)
	fmt.Fprintf(
		w,
		"public_key fingerprint\t%s\n",
		mtc.VerifierFingerprint(p.PublicKey),
	)
	w.Flush()
	return nil
}

func main() {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "cpuprofile",
				Usage: "write cpu profile to file",
			},
		},
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
						Flags: []cli.Flag{
							&cli.DurationFlag{
								Name:    "batch-duration",
								Aliases: []string{"b"},
								Usage:   "time between batches",
							},
							&cli.DurationFlag{
								Name:    "lifetime",
								Aliases: []string{"l"},
								Usage:   "lifetime of an assertion",
							},
							&cli.DurationFlag{
								Name:    "storage-duration",
								Aliases: []string{"s"},
								Usage:   "time to serve assertions",
							},
						},
					},
					{
						Name:   "show-queue",
						Usage:  "prints the queue",
						Action: handleCaShowQueue,
					},
					{
						Name:   "issue",
						Usage:  "certify and issue queued assertions",
						Action: handleCaIssue,
					},
					{
						Name:   "queue",
						Usage:  "queue assertion for issuance",
						Action: handleCaQueue,
						Flags: []cli.Flag{
							&cli.StringSliceFlag{
								Name:     "dns",
								Aliases:  []string{"d"},
								Category: "Claim",
							},
							&cli.StringSliceFlag{
								Name:     "dns-wildcard",
								Aliases:  []string{"w"},
								Category: "Claim",
							},
							&cli.StringSliceFlag{
								Name:     "ip4",
								Category: "Claim",
							},
							&cli.StringSliceFlag{
								Name:     "ip6",
								Category: "Claim",
							},

							&cli.StringFlag{
								Name:     "tls-pem",
								Category: "Subject",
								Usage:    "path to PEM encoded subject public key",
							},
							&cli.StringFlag{
								Name:     "tls-der",
								Category: "Subject",
								Usage:    "path to DER encoded subject public key",
							},
							&cli.StringFlag{
								Name:     "tls-scheme",
								Category: "Subject",
								Usage:    "TLS signature scheme to be used by subject",
							},
							&cli.StringFlag{
								Name:     "checksum",
								Category: "Other",
								Usage:    "Only proceed if checksum matches",
							},
							&cli.IntFlag{
								Name:     "debug-repeat",
								Category: "Debug",
								Usage:    "Queue the same assertion several times",
								Value:    1,
							},
						},
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
					{
						Name:      "signed-validity-window",
						Usage:     "parses signed-validity-window file",
						Action:    handleInspectSignedValidityWindow,
						ArgsUsage: "[path]",
					},
					{
						Name:      "abridged-assertions",
						Usage:     "parses abridged-assertions file",
						Action:    handleInspectAbridgedAssertions,
						ArgsUsage: "[path]",
					},
				},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "ca-params",
						Usage:   "path to CA parameters required to parse some files",
						Aliases: []string{"p"},
					},
				},
			},
		},
		Before: func(cc *cli.Context) error {
			if path := cc.String("cpuprofile"); path != "" {
				var err error
				fCpuProfile, err = os.Create(path)
				if err != nil {
					return fmt.Errorf("create(%s): %w", path, err)
				}
				pprof.StartCPUProfile(fCpuProfile)
			}
			return nil
		},
		After: func(cc *cli.Context) error {
			if fCpuProfile != nil {
				pprof.StopCPUProfile()
			}
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		if err != errArgs {
			fmt.Printf("error: %v\n", err.Error())
		}
		os.Exit(1)
	}
}
