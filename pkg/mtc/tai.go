package mtc

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"strconv"
	"strings"
)

// A TrustAnchorIdentifier (TAI) is used to identify a CA, or a specific batch.
//
// TAI are OIDs relative to the Private Enterprise Numbers (PEN)
// arc 1.3.6.1.4.1.
type TrustAnchorIdentifier struct {
	Issuer      RelativeOID
	BatchNumber uint32
}

type RelativeOID []byte

func (tai *TrustAnchorIdentifier) ProofType(store CAStore) ProofType {
	return store.Lookup(tai.Issuer).ProofType
}

func (oid *RelativeOID) segments() []uint32 {
	var res []uint32
	cur := uint32(0)
	for i := 0; i < len(*oid); i++ {
		cur = (cur << 7) | uint32((*oid)[i]&0x7f)

		if (*oid)[i]&0x80 == 0 {
			res = append(res, cur)
			cur = 0
		}
	}
	return res
}

func (tai *TrustAnchorIdentifier) UnmarshalBinary(buf []byte) error {
	s := cryptobyte.String(buf)
	err := tai.unmarshal(&s)
	if err != nil {
		return err
	}
	if !s.Empty() {
		return ErrExtraBytes
	}
	return nil
}

func (oid *RelativeOID) String() string {
	if oid == nil {
		return "nil"
	}

	var buf bytes.Buffer

	first := true
	for _, s := range oid.segments() {
		if !first {
			_, _ = fmt.Fprintf(&buf, ".")
		}
		first = false
		_, _ = fmt.Fprintf(&buf, "%d", s)
	}
	return buf.String()
}

func (oid *RelativeOID) FromSegments(segments []uint32) error {
	var buf bytes.Buffer
	for _, v := range segments {
		for j := 4; j >= 0; j-- {
			cur := v >> (j * 7)
			if cur != 0 || j == 0 {
				toWrite := byte(cur & 0x7f)
				if j != 0 {
					toWrite |= 0x80
				}
				buf.WriteByte(toWrite)
			}
		}
	}
	*oid = buf.Bytes()
	if len(*oid) > 255 {
		return errors.New("OID: over 255 bytes")
	}
	return nil
}

func (oid *RelativeOID) UnmarshalText(text []byte) error {
	bits := strings.Split(string(text), ".")
	var segments []uint32
	for i, bit := range bits {
		v, err := strconv.ParseUint(bit, 10, 32)
		if err != nil {
			return fmt.Errorf("OID: subidentifier %d: %v", i, err)
		}
		segments = append(segments, uint32(v))
	}
	err := oid.FromSegments(segments)
	if err != nil {
		return err
	}
	if len(*oid) > 255 {
		return errors.New("OID: over 255 bytes")
	}
	return nil
}

func (oid *RelativeOID) MarshalBinary() ([]byte, error) {
	if oid == nil || len(*oid) == 0 {
		return nil, errors.New("can't marshal uninitialized RelativeOID")
	}

	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(*oid)
	})
	return b.Bytes()
}

func (oid *RelativeOID) Equal(rhs *RelativeOID) bool {
	if rhs == nil {
		return false
	}
	if len(*oid) == len(*rhs) {
		for i, v := range *oid {
			if v != (*rhs)[i] {
				return false
			}
		}
		return true
	}
	return false
}

func (tai *TrustAnchorIdentifier) MarshalBinary() ([]byte, error) {
	if tai == nil || tai.Issuer == nil || len(tai.Issuer) == 0 {
		return nil, errors.New("can't marshal uninitialized TrustAnchorIdentifier")
	}
	batch := RelativeOID{}
	err := batch.FromSegments([]uint32{tai.BatchNumber})
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(tai.Issuer)
		b.AddBytes(batch)
	})
	return b.Bytes()
}

func (tai *TrustAnchorIdentifier) unmarshal(s *cryptobyte.String) error {
	var oidBytes []byte
	if !copyUint8LengthPrefixed(s, &oidBytes) || len(oidBytes) == 0 {
		return ErrTruncated
	}

	cur := uint64(0)
	child := 0

	for i := 0; i < len(oidBytes); i++ {
		if cur == 0 && (oidBytes)[i] == 0x80 {
			return errors.New("TrustAnchorIdentifier: not normalized; starts with 0x80")
		}
		cur = (cur << 7) | uint64((oidBytes)[i]&0x7f)

		if cur > 0xffffffff {
			return fmt.Errorf("TrustAnchorIdentifier: overflow of sub-identifier %d", child)
		}

		if (oidBytes)[i]&0x80 == 0 {
			cur = 0
			child++
		} else if i == len(oidBytes)-1 {
			return errors.New("TrustAnchorIdentifier: ends on continuation")
		}
	}

	oid := RelativeOID(oidBytes)
	segments := oid.segments()
	tai.BatchNumber = segments[len(segments)-1]
	err := oid.FromSegments(segments[:len(segments)-1])
	if err != nil {
		return err
	}
	tai.Issuer = oid
	return nil
}
