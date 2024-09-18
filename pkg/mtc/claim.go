package mtc

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"net"
	"regexp"
	"slices"
	"sort"
	"strings"
)

type ClaimType uint16

const (
	DnsClaimType ClaimType = iota
	DnsWildcardClaimType
	Ipv4ClaimType
	Ipv6ClaimType
)

// Claims is a list of claims.
type Claims struct {
	DNS         []string
	DNSWildcard []string
	IPv4        []net.IP
	IPv6        []net.IP
	Unknown     []UnknownClaim
}

// UnknownClaim represents a claim we do not how to interpret.
type UnknownClaim struct {
	Type ClaimType
	Info []byte
}

var domainLabelRegex = regexp.MustCompile("^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$")

func (c *Claims) String() string {
	var bits []string
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
			return nil, errors.New("empty domain name")
		}
		if len(domain) >= 256 {
			return nil, errors.New("domain name too long")
		}
		splitDomain := strings.Split(domain, ".")
		for _, label := range splitDomain {
			if len(label) >= 64 {
				return nil, errors.New("label in domain name too long")
			}
			if !domainLabelRegex.Match([]byte(label)) {
				return nil, errors.New(
					"label in domain contains invalid characters")
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
				return errors.New("claims duplicated or not sorted")
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
				return errors.New("domain claim must list at least one domain")
			}

			for !packed.Empty() {
				var domain []byte
				if !packed.ReadUint8LengthPrefixed((*cryptobyte.String)(&domain)) {
					return ErrTruncated
				}

				domains = append(domains, string(domain))
			}

			sorted, err := sortAndCheckDomainNames(domains)
			if err != nil {
				return err
			}
			if !slices.Equal(sorted, domains) {
				return errors.New("domains were not sorted")
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
				return errors.New("IP claim must list at least one IP")
			}

			first := true
			var previousIp net.IP
			for !packed.Empty() {
				var ip net.IP = make([]byte, entrySize)
				if !packed.CopyBytes(ip) {
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
			clm := UnknownClaim{
				Type: claimType,
				Info: make([]byte, len(claimInfo)),
			}
			copy(clm.Info, claimInfo)
			c.Unknown = append(
				c.Unknown,
				clm,
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
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
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
				return errors.New("not a valid IP address")
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
					b.AddBytes(ip)
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
				return nil, errors.New("parseable UnknownClaim")
			}
		} else {
			if claim.Type <= c.Unknown[i-1].Type {
				return nil, errors.New("duplicate or unsorted unknown claims")
			}
		}

		b.AddUint16(uint16(claim.Type))
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(claim.Info)
		})
	}

	return b.Bytes()
}
