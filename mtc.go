package mtc

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

type CAParams struct {
	IssuerId           string
	PublicKey          Verifier
	StartTime          uint
	BatchDuration      uint
	Lifetime           uint
	ValidityWindowSize uint
	HttpServer         string
}

func (p *CAParams) Validate() error {
	if len(p.IssuerId) > 32 {
		return errors.New("issuer_id must be 32 bytes or less")
	}
	if len(p.IssuerId) == 0 {
		return errors.New("issuer_id can't be empty")
	}
	if p.Lifetime%p.BatchDuration != 0 {
		return errors.New("lifetime must be a multiple of batch_duration")
	}
	if p.ValidityWindowSize != p.Lifetime/p.BatchDuration {
		return errors.New("validity_window_size ≠ lifetime / batch_duration")
	}
	return nil
}

var (
	// ErrTruncated is a parsing error returned when the input seems to have
	// been truncated.
	ErrTruncated = errors.New("Input truncated")

	// ErrExtraBytes is a parsing error returned when there are extraneous
	// bytes at the end of, or within, the data.
	ErrExtraBytes = errors.New("Unexpected extra (internal) bytes")
)

// Copy of tls.SignatureScheme to prevent cycling dependencies
type SignatureScheme uint16

const (
	tlsPSSWithSHA256          SignatureScheme = 0x0804
	tlsPSSWithSHA384          SignatureScheme = 0x0805
	tlsPSSWithSHA512          SignatureScheme = 0x0806
	tlsECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	tlsECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	tlsECDSAWithP521AndSHA512 SignatureScheme = 0x0603
	tlsEd25519                SignatureScheme = 0x0807
)

const (
	hashLen = 32
)

type ClaimType uint16

const (
	DnsClaimType ClaimType = iota
	DnsWildcardClaimType
	Ipv4ClaimType
	Ipv6ClaimType
)

type SubjectType uint16

const (
	TlsSubjectType SubjectType = iota
)

type SubjectBase interface {
	Type() SubjectType
	Info() []byte
}

type AbridgedSubject interface {
	SubjectBase
}

type Subject interface {
	SubjectBase
	Abridge() AbridgedSubject
}

func NewTLSSubject(scheme SignatureScheme, pk crypto.PublicKey) (*TLSSubject, error) {
	ver, err := NewVerifier(scheme, pk)
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint16(uint16(scheme))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ver.Bytes())
	})
	packed, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	return &TLSSubject{
		pk:     ver,
		packed: packed,
	}, nil
}

type TLSSubject struct {
	pk     Verifier
	packed []byte
}

func (s *TLSSubject) Verifier() (Verifier, error) {
	if s.pk != nil {
		return s.pk, nil
	}

	ss := cryptobyte.String(s.packed)
	var (
		scheme    SignatureScheme
		publicKey cryptobyte.String
	)
	if !ss.ReadUint16((*uint16)(&scheme)) ||
		!ss.ReadUint16LengthPrefixed(&publicKey) {
		return nil, ErrTruncated
	}
	if !ss.Empty() {
		return nil, ErrExtraBytes
	}

	pk, err := UnmarshalVerifier(scheme, []byte(publicKey))
	if err != nil {
		return nil, err
	}

	s.pk = pk
	return pk, nil
}

func (s *TLSSubject) Type() SubjectType { return TlsSubjectType }

func (s *TLSSubject) Info() []byte {
	return s.packed
}

func (s *TLSSubject) Abridge() AbridgedSubject {
	return &AbridgedTLSSubject{
		PublicKeyHash:   sha256.Sum256(s.pk.Bytes()),
		SignatureScheme: s.pk.Scheme(),
	}
}

type AbridgedTLSSubject struct {
	SignatureScheme SignatureScheme
	PublicKeyHash   [hashLen]byte
}

func (s *AbridgedTLSSubject) Type() SubjectType { return TlsSubjectType }

func (s *AbridgedTLSSubject) Info() []byte {
	var b cryptobyte.Builder
	b.AddUint16(uint16(s.SignatureScheme))
	b.AddBytes(s.PublicKeyHash[:])
	buf, _ := b.Bytes()
	return buf
}

// Used for either an unknown (abridged) subject
type UnknownSubject struct {
	typ  SubjectType
	info []byte
}

func (s *UnknownSubject) Type() SubjectType { return s.typ }
func (s *UnknownSubject) Info() []byte      { return s.info }
func (s *UnknownSubject) Abridge() AbridgedSubject {
	panic("Can't abridge unknown subject")
}

type Assertion struct {
	Subject Subject
	Claims  Claims
}

func (a *Assertion) Abridge() (ret AbridgedAssertion) {
	ret.Claims = a.Claims
	ret.Subject = a.Subject.Abridge()
	return
}

func (a *Assertion) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(uint16(a.Subject.Type()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // subject_info
		b.AddBytes(a.Subject.Info())
	})
	claims, err := a.Claims.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(claims)
	})
	return b.Bytes()
}

func (a *Assertion) UnmarshalBinary(data []byte) error {
	var (
		subjectType SubjectType
		subjectInfo cryptobyte.String
		claims      cryptobyte.String
	)
	s := cryptobyte.String(data)
	if !s.ReadUint16((*uint16)(&subjectType)) ||
		!s.ReadUint16LengthPrefixed(&subjectInfo) ||
		!s.ReadUint16LengthPrefixed(&claims) {
		return ErrTruncated
	}

	if !s.Empty() {
		return ErrExtraBytes
	}

	if err := a.Claims.UnmarshalBinary([]byte(claims)); err != nil {
		return fmt.Errorf("Failed to unmarshal claims: %w", err)
	}

	switch subjectType {
	case TlsSubjectType:
		a.Subject = &TLSSubject{
			packed: []byte(subjectInfo),
		}
	default:
		a.Subject = &UnknownSubject{
			typ:  subjectType,
			info: []byte(subjectInfo),
		}
	}

	return nil
}

type AbridgedAssertion struct {
	Subject AbridgedSubject
	Claims  Claims
}

func (a *AbridgedAssertion) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(uint16(a.Subject.Type()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // abridged_subject_info
		b.AddBytes(a.Subject.Info())
	})
	claims, err := a.Claims.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(claims)
	})
	return b.Bytes()
}

func (a *AbridgedAssertion) UnmarshalBinary(data []byte) error {
	var (
		subjectType SubjectType
		subjectInfo cryptobyte.String
		claims      cryptobyte.String
	)
	s := cryptobyte.String(data)
	if !s.ReadUint16((*uint16)(&subjectType)) ||
		!s.ReadUint16LengthPrefixed(&subjectInfo) ||
		!s.ReadUint16LengthPrefixed(&claims) {
		return ErrTruncated
	}

	if !s.Empty() {
		return ErrExtraBytes
	}

	if err := a.Claims.UnmarshalBinary([]byte(claims)); err != nil {
		return fmt.Errorf("Failed to unmarshal claims: %w", err)
	}

	switch subjectType {
	case TlsSubjectType:
		var (
			pkHash  []byte
			subject AbridgedTLSSubject
		)
		if !subjectInfo.ReadUint16((*uint16)(&subject.SignatureScheme)) ||
			!subjectInfo.ReadBytes(&pkHash, hashLen) {
			return ErrTruncated
		}
		if !subjectInfo.Empty() {
			return ErrExtraBytes
		}
		copy(subject.PublicKeyHash[:], pkHash)
		a.Subject = &subject
	default:
		a.Subject = &UnknownSubject{
			typ:  subjectType,
			info: []byte(subjectInfo),
		}
	}

	return nil
}

// List of claims.
type Claims struct {
	DNS         []string
	DNSWildcard []string
	IPv4        []net.IP
	IPv6        []net.IP
	Unknown     []UnknownClaim
}

// Represents a claim we do not how to interpret.
type UnknownClaim struct {
	Type ClaimType
	Info []byte
}

var domainLabelRegex = regexp.MustCompile("^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$")

func (c Claims) String() string {
	bits := []string{}
	if len(c.DNS) != 0 {
		bits = append(bits, c.DNS...)
	}
	if len(c.DNSWildcard) != 0 {
		for _, domain := range c.DNSWildcard {
			bits = append(bits, "*."+domain)
		}
	}
	if len(c.IPv4) != 0 {
		for _, ip := range c.IPv4 {
			bits = append(bits, ip.String())
		}
	}
	if len(c.IPv6) != 0 {
		for _, ip := range c.IPv6 {
			bits = append(bits, ip.String())
		}
	}
	if len(c.Unknown) != 0 {
		for _, claim := range c.Unknown {
			bits = append(bits, fmt.Sprintf(
				"<unknown claim of type %d>",
				uint16(claim.Type),
			))
		}
	}
	return strings.Join(bits, ", ")
}

// Checks whether the given strings are valid domain names, and sorts them
// hierarchically.
func sortAndCheckDomainNames(ds []string) ([]string, error) {
	splitDomains := make([][]string, 0, len(ds))

	for _, domain := range ds {
		if len(domain) == 0 {
			return nil, errors.New("Empty domain name")
		}
		if len(domain) >= 256 {
			return nil, errors.New("Domain name too long")
		}
		splitDomain := strings.Split(domain, ".")
		for _, label := range splitDomain {
			if len(label) >= 64 {
				return nil, errors.New("Label in domain name too long")
			}
			if !domainLabelRegex.Match([]byte(label)) {
				return nil, errors.New(
					"Label in domain contains invalid characters")
			}
		}
		splitDomains = append(splitDomains, splitDomain)
	}
	sort.Slice(splitDomains, func(i, j int) bool {
		for k := 0; ; k++ {
			if len(splitDomains[j]) == k {
				return false
			}
			if len(splitDomains[i]) == k {
				return true
			}
			a := splitDomains[i][len(splitDomains[i])-k-1]
			b := splitDomains[j][len(splitDomains[j])-k-1]
			if a == b {
				continue
			}
			return a < b
		}
	})

	ret := make([]string, 0, len(ds))
	for _, splitDomain := range splitDomains {
		ret = append(ret, strings.Join(splitDomain, "."))
	}

	return ret, nil
}

func (c *Claims) UnmarshalBinary(data []byte) error {
	*c = Claims{}

	s := cryptobyte.String(data)

	var previousType ClaimType
	first := true

	for !s.Empty() {
		var (
			claimInfo cryptobyte.String
			claimType ClaimType
		)

		if !s.ReadUint16((*uint16)(&claimType)) ||
			!s.ReadUint16LengthPrefixed(&claimInfo) {
			return ErrTruncated
		}

		if first {
			first = false
		} else {
			if previousType >= claimType {
				return errors.New("Claims duplicated or not sorted")
			}
			previousType = claimType
		}

		switch claimType {
		case DnsClaimType, DnsWildcardClaimType:
			var (
				packed  cryptobyte.String
				domains []string
			)

			if !claimInfo.ReadUint16LengthPrefixed(&packed) {
				return ErrTruncated
			}

			if !claimInfo.Empty() {
				return ErrExtraBytes
			}

			if packed.Empty() {
				return errors.New("Domain claim must list at least one domain")
			}

			for !packed.Empty() {
				var domain []byte
				if !packed.ReadUint16LengthPrefixed((*cryptobyte.String)(&domain)) {
					return ErrTruncated
				}

				domains = append(domains, string(domain))
			}

			sorted, err := sortAndCheckDomainNames(domains)
			if err != nil {
				return err
			}
			if !slices.Equal(sorted, domains) {
				return errors.New("Domains were not sorted")
			}

			if claimType == DnsClaimType {
				c.DNS = domains
			} else {
				c.DNSWildcard = domains
			}

		case Ipv4ClaimType, Ipv6ClaimType:
			var (
				packed cryptobyte.String
				ips    []net.IP
			)

			if !claimInfo.ReadUint16LengthPrefixed(&packed) {
				return ErrTruncated
			}

			if !claimInfo.Empty() {
				return ErrExtraBytes
			}

			entrySize := 16
			if claimType == Ipv4ClaimType {
				entrySize = 4
			}

			if packed.Empty() {
				return errors.New("IP claim must list at leats one IP")
			}

			first := true
			var previousIp net.IP
			for !packed.Empty() {
				var ip net.IP
				if !packed.ReadBytes((*[]byte)(&ip), entrySize) {
					return ErrTruncated
				}
				if first {
					first = false
				} else {
					if slices.Compare(previousIp, ip) >= 0 {
						return errors.New("IPs were not sorted")
					}
					previousIp = ip
				}

				ips = append(ips, ip)
			}

			if claimType == Ipv4ClaimType {
				c.IPv4 = ips
			} else {
				c.IPv6 = ips
			}

		default:
			c.Unknown = append(
				c.Unknown,
				UnknownClaim{
					Type: claimType,
					Info: []byte(claimInfo),
				},
			)
		}
	}

	return nil
}

func (c *Claims) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder

	marshalDomains := func(domains []string, claimType ClaimType) error {
		if len(domains) == 0 {
			return nil
		}
		sorted, err := sortAndCheckDomainNames(domains)
		if err != nil {
			return err
		}

		b.AddUint16(uint16(claimType))
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // claim_info
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // dns_names
				for _, domain := range sorted {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(domain))
					})
				}
			})
		})
		return nil
	}

	if err := marshalDomains(c.DNS, DnsClaimType); err != nil {
		return nil, err
	}
	if err := marshalDomains(c.DNSWildcard, DnsWildcardClaimType); err != nil {
		return nil, err
	}

	marshalIPs := func(ips []net.IP, ipv4 bool) error {
		if len(ips) == 0 {
			return nil
		}

		sorted := make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			if ipv4 {
				ip = ip.To4()
			} else {
				ip = ip.To16()
			}
			if ip == nil {
				return errors.New("Not a valid IP address")
			}
			sorted = append(sorted, ip)
		}
		sort.Slice(sorted, func(i, j int) bool {
			return slices.Compare(sorted[i], sorted[j]) < 0
		})

		if ipv4 {
			b.AddUint16(uint16(Ipv4ClaimType))
		} else {
			b.AddUint16(uint16(Ipv6ClaimType))
		}
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // claim_info
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // addresses
				for _, ip := range sorted {
					b.AddBytes([]byte(ip))
				}
			})
		})
		return nil
	}

	if err := marshalIPs(c.IPv4, true); err != nil {
		return nil, err
	}
	if err := marshalIPs(c.IPv6, false); err != nil {
		return nil, err
	}

	for i := 0; i < len(c.Unknown); i++ {
		claim := c.Unknown[i]
		if i == 0 {
			if claim.Type <= Ipv6ClaimType {
				return nil, errors.New("Parseable UnknownClaim")
			}
		} else {
			if claim.Type <= c.Unknown[i-1].Type {
				return nil, errors.New("Duplicate or unsorted unknown claims")
			}
		}

		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(claim.Info)
		})
	}

	return b.Bytes()
}
