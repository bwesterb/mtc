package main

import (
	"errors"
	"maps"
	"slices"

	"github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/ca"
	"github.com/bwesterb/mtc/umbilical"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/cryptobyte"

	"bufio"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/pprof"
	"text/tabwriter"
	"time"
)

var (
	errNoCaParams = errors.New("missing ca-params flag")
	errArgs       = errors.New("Wrong number of arguments")
	fCpuProfile   *os.File
	evPolicyMap   = map[string]mtc.EvidencePolicyType{
		"empty":     mtc.EmptyEvidencePolicyType,
		"umbilical": mtc.UmbilicalEvidencePolicyType,
	}
)

// Writes buf either to stdout (if path is empty) or path.
func writeToFileOrStdout(path string, buf []byte) error {
	if path != "" {
		err := os.WriteFile(path, buf, 0644)
		if err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
		return nil
	}

	_, err := os.Stdout.Write(buf)
	if err != nil {
		return fmt.Errorf("writing to stdout: %w", err)
	}

	return nil
}

// Flags used to create or specify an assertion request.
// Used in `mtc ca queue' and 'mtc ca cert'.
// Includes the in-file flag, if inFile is true.
func assertionRequestFlags(inFile bool) []cli.Flag {
	ret := []cli.Flag{
		&cli.StringSliceFlag{
			Name:     "dns",
			Aliases:  []string{"d"},
			Category: "Assertion",
		},
		&cli.StringSliceFlag{
			Name:     "dns-wildcard",
			Aliases:  []string{"w"},
			Category: "Assertion",
		},
		&cli.StringSliceFlag{
			Name:     "ip4",
			Category: "Assertion",
		},
		&cli.StringSliceFlag{
			Name:     "ip6",
			Category: "Assertion",
		},

		&cli.StringFlag{
			Name:     "tls-pem",
			Category: "Assertion",
			Usage:    "path to PEM encoded subject public key",
		},
		&cli.StringFlag{
			Name:     "tls-der",
			Category: "Assertion",
			Usage:    "path to DER encoded subject public key",
		},
		&cli.StringFlag{
			Name:     "tls-scheme",
			Category: "Assertion",
			Usage:    "TLS signature scheme to be used by subject",
		},
		&cli.StringFlag{
			Name:     "checksum",
			Category: "Assertion",
			Usage:    "Only proceed if assertion matches checksum",
		},
		&cli.StringFlag{
			Name:     "not_after",
			Category: "Assertion",
			Usage:    "An initial not_after value for the assertion request in RFC3339 format, which can be used to shorten an assertion's lifetime",
		},
		&cli.StringFlag{
			Name:     "from-x509-pem",
			Category: "Assertion",
			Aliases:  []string{"x"},
			Usage:    "Suggest assertion from X.509 PEM encoded certificate (chain)",
		},
		&cli.StringFlag{
			Name:     "from-x509-server",
			Category: "Assertion",
			Aliases:  []string{"X"},
			Usage:    "Suggest assertion for TLS server with existing X.509 chain",
		},
	}
	if inFile {
		ret = append(
			ret,
			&cli.StringFlag{
				Name:     "in-file",
				Category: "Assertion",
				Aliases:  []string{"i"},
				Usage:    "Read assertion request from the given file",
			},
		)
	}

	return ret
}

func assertionRequestFromFlags(cc *cli.Context) (*mtc.AssertionRequest, error) {
	ar, err := assertionRequestFromFlagsUnchecked(cc)
	if err != nil {
		return nil, err
	}

	err = ar.Check()
	if err != nil {
		return nil, err
	}

	return ar, nil
}

func assertionRequestFromFlagsUnchecked(cc *cli.Context) (*mtc.AssertionRequest, error) {
	var (
		checksum []byte
		notAfter time.Time
		err      error
	)

	if cc.String("checksum") != "" {
		checksum, err = hex.DecodeString(cc.String("checksum"))
		if err != nil {
			return nil, fmt.Errorf("parsing checksum: %w", err)
		}
	}

	if cc.String("not_after") != "" {
		notAfter, err = time.Parse(time.RFC3339, cc.String("not_after"))
		if err != nil {
			return nil, fmt.Errorf("parsing not_after: %w", err)
		}
	}

	assertionPath := cc.String("in-file")
	if assertionPath != "" {
		assertionBuf, err := os.ReadFile(assertionPath)
		if err != nil {
			return nil, fmt.Errorf(
				"reading assertion request %s: %w",
				assertionPath,
				err,
			)
		}

		for _, flag := range []string{
			"dns",
			"dns-wildcard",
			"ip4",
			"ip6",
			"tls-der",
			"tls-pem",
			"from-x509-server",
			"from-x509-pem",
		} {
			if cc.IsSet(flag) {
				return nil, fmt.Errorf(
					"Can't specify --in-file and --%s together",
					flag,
				)
			}
		}

		var ar mtc.AssertionRequest
		err = ar.UnmarshalBinary(assertionBuf)
		if err != nil {
			return nil, fmt.Errorf(
				"parsing assertion request %s: %w",
				assertionPath,
				err,
			)
		}
		return &ar, nil
	}

	var (
		a      mtc.Assertion
		el     mtc.EvidenceList
		scheme mtc.SignatureScheme
	)

	if cc.IsSet("tls-scheme") {
		scheme = mtc.SignatureSchemeFromString(cc.String("tls-scheme"))
		if scheme == 0 {
			return nil, fmt.Errorf("Unknown TLS signature scheme: %s", scheme)
		}
	}

	if cc.IsSet("from-x509-pem") || cc.IsSet("from-x509-server") {
		var certs []*x509.Certificate

		if cc.IsSet("from-x509-server") {
			tlsAddr := cc.String("from-x509-server")
			certs, err = umbilical.GetChainFromTLSServer(tlsAddr)
			if err != nil {
				return nil, fmt.Errorf("from-x509-server: %v", err)
			}
		}

		if cc.IsSet("from-x509-pem") {
			x509Path := cc.String("from-x509-pem")
			x509Buf, err := os.ReadFile(x509Path)
			if err != nil {
				return nil, fmt.Errorf("reading x509 chain %s: %w", x509Path, err)
			}

			rest := []byte(x509Buf)
			for i := 0; true; i++ {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf(
						"parsing x509 certificate %d in %s: %s",
						i, x509Path, err,
					)
				}

				certs = append(certs, cert)
			}

			if len(certs) == 0 {
				return nil, fmt.Errorf(
					"reading x509 chain %s: no (PEM encoded) certificates found",
					x509Path,
				)
			}
		}

		a, err = umbilical.SuggestedAssertionFromX509(certs[0], scheme)
		if err != nil {
			return nil, fmt.Errorf("from-x509: %s", err)
		}

		ev, err := mtc.NewUmbilicalEvidence(certs)
		if err != nil {
			return nil, err
		}
		el = append(el, ev)
	}

	// Setting any claim will overwrite those suggested by the
	// X509 certificate.
	if cc.IsSet("dns") || cc.IsSet("dns-wildcard") || cc.IsSet("ip4") ||
		cc.IsSet("ip6") {

		a.Claims = mtc.Claims{
			DNS:         cc.StringSlice("dns"),
			DNSWildcard: cc.StringSlice("dns-wildcard"),
		}

		for _, ip := range cc.StringSlice("ip4") {
			a.Claims.IPv4 = append(a.Claims.IPv4, net.ParseIP(ip))
		}

		for _, ip := range cc.StringSlice("ip6") {
			a.Claims.IPv6 = append(a.Claims.IPv6, net.ParseIP(ip))
		}
	}

	subjectFlagCount := 0
	for _, flag := range []string{"tls-pem", "tls-der", "from-x509-pem",
		"from-x509-server"} {
		if cc.IsSet(flag) {
			subjectFlagCount++
		}
	}
	if subjectFlagCount != 1 {
		return nil, errors.New(
			"expect exactly one of tls-pem, tls-der, from-x509-server," +
				" or from-x509-pem flags",
		)
	}

	if a.Subject == nil {
		usingPem := false
		subjectPath := cc.String("tls-der")
		if cc.String("tls-pem") != "" {
			usingPem = true
			subjectPath = cc.String("tls-pem")
		}

		subjectBuf, err := os.ReadFile(subjectPath)
		if err != nil {
			return nil, fmt.Errorf("reading subject %s: %w", subjectPath, err)
		}

		if usingPem {
			block, _ := pem.Decode([]byte(subjectBuf))
			if block == nil {
				return nil, fmt.Errorf(
					"reading subject %s: failed to parse PEM block",
					subjectPath,
				)
			}
			subjectBuf = block.Bytes
		}

		pub, err := x509.ParsePKIXPublicKey(subjectBuf)
		if err != nil {
			return nil, fmt.Errorf("parsing subject %s: %w", subjectPath, err)
		}

		if !cc.IsSet("tls-scheme") {
			schemes := mtc.SignatureSchemesFor(pub)
			if len(schemes) == 0 {
				return nil, fmt.Errorf(
					"no matching signature scheme for that public key",
				)
			}
			if len(schemes) >= 2 {
				return nil, fmt.Errorf(
					"specify --tls-scheme with one of %s",
					schemes,
				)
			}
			scheme = schemes[0]
		}

		subj, err := mtc.NewTLSSubject(scheme, pub)
		if err != nil {
			return nil, fmt.Errorf("creating subject: %w", err)
		}

		a.Subject = subj
	}

	return &mtc.AssertionRequest{
		Assertion: a,
		Evidence:  el,
		Checksum:  checksum,
		NotAfter:  notAfter,
	}, nil
}

func handleCaQueue(cc *cli.Context) error {
	ar, err := assertionRequestFromFlags(cc)
	if err != nil {
		return err
	}

	h, err := ca.Open(cc.String("ca-path"))
	if err != nil {
		return err
	}
	defer h.Close()

	return h.QueueMultiple(func(yield func(ar mtc.AssertionRequest) error) error {
		for i := 0; i < cc.Int("debug-repeat"); i++ {
			ar2 := *ar
			if cc.Bool("debug-vary") {
				ar2.Checksum = nil
				ar2.Assertion.Claims.DNS = append(
					ar2.Assertion.Claims.DNS,
					fmt.Sprintf("%d.example.com", i),
				)
			}
			if err := yield(ar2); err != nil {
				return err
			}
		}
		return nil
	})
}

func handleNewAssertionRequest(cc *cli.Context) error {
	ar, err := assertionRequestFromFlags(cc)
	if err != nil {
		return err
	}

	buf, err := ar.MarshalBinary()
	if err != nil {
		return err
	}

	if err := writeToFileOrStdout(cc.String("out-file"), buf); err != nil {
		return err
	}

	return nil
}

func handleCaIssue(cc *cli.Context) error {
	h, err := ca.Open(cc.String("ca-path"))
	if err != nil {
		return err
	}
	defer h.Close()

	return h.Issue()
}

func handleCaCert(cc *cli.Context) error {
	h, err := ca.Open(cc.String("ca-path"))
	if err != nil {
		return err
	}
	defer h.Close()

	ar, err := assertionRequestFromFlags(cc)
	if err != nil {
		return err
	}

	cert, err := h.CertificateFor(ar.Assertion)
	if err != nil {
		return err
	}

	buf, err := cert.MarshalBinary()
	if err != nil {
		return err
	}

	if err := writeToFileOrStdout(cc.String("out-file"), buf); err != nil {
		return err
	}

	return nil
}

func handleCaEvidence(cc *cli.Context) error {
	h, err := ca.Open(cc.String("ca-path"))
	if err != nil {
		return err
	}
	defer h.Close()

	ar, err := assertionRequestFromFlags(cc)
	if err != nil {
		return err
	}

	ev, err := h.EvidenceFor(ar.Assertion)
	if err != nil {
		return err
	}

	buf, err := ev.MarshalBinary()
	if err != nil {
		return err
	}

	if err := writeToFileOrStdout(cc.String("out-file"), buf); err != nil {
		return err
	}

	return nil
}

func handleCaShowQueue(cc *cli.Context) error {
	h, err := ca.Open(cc.String("ca-path"))
	if err != nil {
		return err
	}
	defer h.Close()

	count := 0

	err = h.WalkQueue(func(ar mtc.AssertionRequest) error {
		count++
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
		err = writeAssertionRequest(w, ar)
		if err != nil {
			return err
		}
		w.Flush()
		fmt.Printf("\n")
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("Total number of assertion requests in queue: %d\n", count)
	return nil
}

func handleCaServe(cc *cli.Context) error {
	path := cc.String("ca-path")
	listenAddr := cc.String("listen-addr")
	if listenAddr == "" {
		h, err := ca.Open(path)
		if err != nil {
			return err
		}
		listenAddr = h.Params().HttpServer
		h.Close()
	}
	s := NewServer(path, listenAddr)
	return s.Serve()
}

func handleCaNew(cc *cli.Context) error {
	if cc.Args().Len() != 2 {
		err := cli.ShowSubcommandHelp(cc)
		if err != nil {
			return err
		}
		return errArgs
	}

	taiString := cc.Args().Get(0)
	oid := mtc.RelativeOID{}
	err := oid.UnmarshalText([]byte(taiString))
	if err != nil {
		return err
	}

	evPolicy, ok := evPolicyMap[cc.String("evidence-policy")]
	if !ok {
		return fmt.Errorf("unknown evidence policy: %s", cc.String("evidence-policy"))
	}

	var umbilicalRoots []byte
	if evPolicy == mtc.UmbilicalEvidencePolicyType {
		if !cc.IsSet("umbilical-roots") {
			return errors.New("umbilical-roots must be set")
		}

		umbilicalRoots, err = os.ReadFile(cc.String("umbilical-roots"))
		if err != nil {
			return fmt.Errorf("reading %s: %w", cc.String("umbilical-roots"), err)
		}
	}

	h, err := ca.New(
		cc.String("ca-path"),
		ca.NewOpts{
			Issuer:     oid,
			HttpServer: cc.Args().Get(1),

			BatchDuration:     cc.Duration("batch-duration"),
			StorageDuration:   cc.Duration("storage-duration"),
			Lifetime:          cc.Duration("lifetime"),
			EvidencePolicy:    evPolicy,
			UmbilicalRootsPEM: umbilicalRoots,
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
		return nil, errNoCaParams
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
			int(sw.ValidityWindow.BatchNumber)+i-int(p.ValidityWindowSize)+1,
			sw.ValidityWindow.TreeHeads[mtc.HashLen*i:mtc.HashLen*(i+1)],
		)
	}

	w.Flush()
	return nil
}

func handleInspectIndex(cc *cli.Context) error {
	buf, err := inspectGetBuf(cc)
	if err != nil {
		return err
	}

	var (
		key            []byte
		seqno          uint64
		offset         uint64
		evidenceOffset uint64
	)

	s := cryptobyte.String(buf)

	total := 0
	fmt.Printf("%64s %7s %7s\n", "key", "seqno", "offset")
	for !s.Empty() {
		if !s.ReadBytes(&key, 32) || !s.ReadUint64(&seqno) || !s.ReadUint64(&offset) || !s.ReadUint64(&evidenceOffset) {
			return errors.New("truncated")
		}

		fmt.Printf("%x %7d %7d %7d\n", key, seqno, offset, evidenceOffset)
		total++
	}

	fmt.Printf("\ntotal number of entries: %d\n", total)

	return nil
}

func handleInspectTree(cc *cli.Context) error {
	buf, err := inspectGetBuf(cc)
	if err != nil {
		return err
	}

	var t mtc.Tree
	err = t.UnmarshalBinary(buf)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintf(w, "number of leaves\t%d\n", t.LeafCount())
	fmt.Fprintf(w, "number of nodes\t%d\n", t.NodeCount())
	fmt.Fprintf(w, "root\t%x\n", t.Root())
	w.Flush()
	return nil
}

func writeAssertionRequest(w *tabwriter.Writer, ar mtc.AssertionRequest) error {
	fmt.Fprintf(w, "checksum\t%x\n", ar.Checksum)
	if ar.NotAfter.IsZero() {
		fmt.Fprintf(w, "not_after\tunset\n")
	} else {
		fmt.Fprintf(w, "not_after\t%v\n", ar.NotAfter.UTC())
	}
	writeAssertion(w, ar.Assertion)
	err := writeEvidenceList(w, ar.Evidence)
	if err != nil {
		return err
	}
	return nil
}

func writeAssertion(w *tabwriter.Writer, a mtc.Assertion) {
	aa := a.Abridge()
	cs := aa.Claims
	subj := aa.Subject
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
}

func writeEvidenceList(w *tabwriter.Writer, el mtc.EvidenceList) error {

	fmt.Fprintf(w, "evidence-list (%d entries)\n", len(el))
	for _, ev := range el {
		switch ev.Type() {
		case mtc.UmbilicalEvidenceType:
			fmt.Fprintf(w, "umbilical\n")
			chain, err := ev.(mtc.UmbilicalEvidence).Chain()
			if err != nil {
				return err
			}
			for j, cert := range chain {
				fmt.Fprintf(w, " certificate\t%d\n", j)
				fmt.Fprintf(w, "  subject\t%s\n", cert.Subject.String())
				fmt.Fprintf(w, "  issuer\t%s\n", cert.Issuer.String())
				fmt.Fprintf(w, "  serial_no\t%x\n", cert.SerialNumber)
				fmt.Fprintf(w, "  not_before\t%s\n", cert.NotBefore)
				fmt.Fprintf(w, "  not_after\t%s\n", cert.NotAfter)
			}
		default:
			fmt.Fprintf(w, "unknown type=%d info=%x\n", ev.Type(), ev.Info())
		}
	}
	return nil
}

func handleInspectCert(cc *cli.Context) error {
	buf, err := inspectGetBuf(cc)
	if err != nil {
		return err
	}
	params, err := inspectGetCAParams(cc)
	if err != nil {
		return err
	}

	caStore := mtc.LocalCAStore{}
	caStore.Add(*params)

	var c mtc.BikeshedCertificate
	err = c.UnmarshalBinary(buf, &caStore)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	writeAssertion(w, c.Assertion)
	fmt.Fprintf(w, "\n")
	tai := c.Proof.TrustAnchorIdentifier()
	fmt.Fprintf(w, "proof_type\t%v\n", tai.ProofType(&caStore))

	fmt.Fprintf(w, "CA OID\t%s\n", tai.Issuer)
	fmt.Fprintf(w, "Batch number\t%d\n", tai.BatchNumber)

	switch proof := c.Proof.(type) {
	case *mtc.MerkleTreeProof:
		fmt.Fprintf(w, "index\t%d\n", proof.Index())
	}

	switch proof := c.Proof.(type) {
	case *mtc.MerkleTreeProof:
		path := proof.Path()
		batch := &mtc.Batch{
			CA:     params,
			Number: tai.BatchNumber,
		}

		if !tai.Issuer.Equal(&params.Issuer) {
			return fmt.Errorf(
				"IssuerId doesn't match: %s ≠ %s",
				params.Issuer,
				tai.Issuer,
			)
		}
		aa := c.Assertion.Abridge()
		root, err := batch.ComputeRootFromAuthenticationPath(
			proof.Index(),
			path,
			&aa,
		)
		if err != nil {
			return fmt.Errorf("computing root: %w", err)
		}

		fmt.Fprintf(w, "recomputed root\t%x\n", root)

		w.Flush()
		fmt.Printf("authentication path\n")
		for i := 0; i < len(path)/mtc.HashLen; i++ {
			fmt.Printf(" %x\n", path[i*mtc.HashLen:(i+1)*mtc.HashLen])
		}
	}

	w.Flush()
	return nil
}

func handleInspectAssertionRequest(cc *cli.Context) error {
	buf, err := inspectGetBuf(cc)
	if err != nil {
		return err
	}

	var ar mtc.AssertionRequest
	err = ar.UnmarshalBinary(buf)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	err = writeAssertionRequest(w, ar)
	if err != nil {
		return err
	}
	w.Flush()
	return nil
}

func handleInspectEvidence(cc *cli.Context) error {

	r, err := inspectGetReader(cc)
	if err != nil {
		return err
	}
	defer r.Close()

	count := 0
	err = mtc.UnmarshalEvidenceLists(
		bufio.NewReader(r),
		func(_ int, el *mtc.EvidenceList) error {
			count++
			w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
			err := writeEvidenceList(w, *el)
			if err != nil {
				return err
			}
			w.Flush()
			fmt.Printf("\n")
			return nil
		},
	)
	if err != nil {
		return err
	}
	fmt.Printf("Total number of evidence lists: %d\n", count)
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
		func(_ int, aa *mtc.AbridgedAssertion) error {
			count++
			cs := aa.Claims
			subj := aa.Subject
			var key [mtc.HashLen]byte
			aa.Key(key[:])
			w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
			fmt.Fprintf(w, "key\t%x\n", key)
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
	fmt.Fprintf(w, "issuer\t%s\n", p.Issuer)
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
						Name:    "ca-path",
						Aliases: []string{"p"},
						Usage:   "path to CA state",
						Value:   ".",
					},
				},
				Subcommands: []*cli.Command{
					{
						Name:      "new",
						Usage:     "creates a new CA",
						Action:    handleCaNew,
						ArgsUsage: "<issuer-oid> <http-server>",
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
							&cli.StringFlag{
								Name:  "evidence-policy",
								Usage: fmt.Sprintf("policy determining assertion evidence requirements (accepted values %v)", slices.Collect(maps.Keys(evPolicyMap))),
								Value: "empty",
							},
							&cli.StringFlag{
								Name:  "umbilical-roots",
								Usage: "path to PEM-encoded accepted roots for umbilical (X.509 chain) evidence",
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
						Flags: append(
							assertionRequestFlags(true),
							&cli.IntFlag{
								Name:     "debug-repeat",
								Category: "Debug",
								Usage:    "Queue the same assertion several times",
								Value:    1,
							},
							&cli.BoolFlag{
								Name:     "debug-vary",
								Category: "Debug",
								Usage:    "Varies each repeated assertion slightly",
							},
						),
					},
					{
						Name:   "cert",
						Usage:  "creates certificate for an issued assertion",
						Action: handleCaCert,
						Flags: append(
							assertionRequestFlags(true),
							&cli.StringFlag{
								Name:    "out-file",
								Usage:   "path to write cert to",
								Aliases: []string{"o"},
							},
						),
					},
					{
						Name:   "evidence",
						Usage:  "fetches evidence for an issued assertion",
						Action: handleCaEvidence,
						Flags: append(
							assertionRequestFlags(true),
							&cli.StringFlag{
								Name:    "out-file",
								Usage:   "path to write evidence to",
								Aliases: []string{"o"},
							},
						),
					},
					{
						Name:   "serve",
						Usage:  "start CA server",
						Action: handleCaServe,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:  "listen-addr",
								Usage: "Address for the server to listen on, in the form 'host:port'",
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
						Usage:     "parses batch's signed-validity-window file",
						Action:    handleInspectSignedValidityWindow,
						ArgsUsage: "[path]",
					},
					{
						Name:      "abridged-assertions",
						Usage:     "parses batch's abridged-assertions file",
						Action:    handleInspectAbridgedAssertions,
						ArgsUsage: "[path]",
					},
					{
						Name:      "assertion-request",
						Usage:     "parses an assertion request",
						Action:    handleInspectAssertionRequest,
						ArgsUsage: "[path]",
					},
					{
						Name:      "evidence",
						Usage:     "parses batch's evidence file",
						Action:    handleInspectEvidence,
						ArgsUsage: "[path]",
					},
					{
						Name:      "tree",
						Usage:     "parses batch's tree file",
						Action:    handleInspectTree,
						ArgsUsage: "[path]",
					},
					{
						Name:      "index",
						Usage:     "parses batch's index file",
						Action:    handleInspectIndex,
						ArgsUsage: "[path]",
					},
					{
						Name:      "cert",
						Usage:     "parses a certificate",
						Action:    handleInspectCert,
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
			{
				Name:   "new-assertion-request",
				Usage:  "creates a new assertion request",
				Action: handleNewAssertionRequest,
				Flags: append(
					assertionRequestFlags(false),
					&cli.StringFlag{
						Name:    "out-file",
						Usage:   "path to write assertion request to",
						Aliases: []string{"o"},
					},
				),
			},
		},
		Before: func(cc *cli.Context) error {
			if path := cc.String("cpuprofile"); path != "" {
				var err error
				fCpuProfile, err = os.Create(path)
				if err != nil {
					return fmt.Errorf("create(%s): %w", path, err)
				}
				err = pprof.StartCPUProfile(fCpuProfile)
				if err != nil {
					return fmt.Errorf("StartCPUProfile: %w", err)
				}
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
