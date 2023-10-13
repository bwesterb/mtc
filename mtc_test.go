package mtc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

// Check if hex is the hexdump of data ignoring whitespace
func hexEqual(t *testing.T, data []byte, hex string) {
	hex = strings.ReplaceAll(hex, " ", "")
	hex = strings.ReplaceAll(hex, "\n", "")
	if hex != fmt.Sprintf("%x", data) {
		t.Fatalf(
			"Expected:\n\n%s\n\nGot:\n\n%s",
			hex,
			hexdump(data),
		)
	}
}

func hexdump(data []byte) string {
	buf := &bytes.Buffer{}

	for i := 0; i < len(data); i += 32 {
		for j := 0; j < 32; j += 4 {
			if j != 0 {
				fmt.Fprintf(buf, " ")
			}
			for k := 0; k < 4; k++ {
				if i+j+k >= len(data) {
					fmt.Fprintf(buf, "  ")
				} else {
					fmt.Fprintf(buf, "%02x", data[i+j+k])
				}
			}
		}
		fmt.Fprintf(buf, "\n")
	}

	return buf.String()
}

func TestDraftExampleAssertion(t *testing.T) {
	var seed [ed25519.SeedSize]byte
	h := sha3.NewShake128()
	h.Write([]byte("MTC Example"))
	h.Read(seed[:])

	privEd := ed25519.NewKeyFromSeed(seed[:])
	pubEd := privEd.Public()
	subjectEd, err := NewTLSSubject(tlsEd25519, pubEd)
	if err != nil {
		t.Fatal(err)
	}
	a := Assertion{
		Subject: subjectEd,
		Claims: Claims{
			DNS: []string{"example.com"},
		},
	}
	buf, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	hexEqual(t, buf,
		`00000024 08070020 c5d2080f a9a489a2 26b58166 dad00be8 120931a7 69c9c6f1
        f8eefafc 38af9065 00130000 000f000d 000b6578 616d706c 652e636f 6d`,
	)
	aa := a.Abridge()
	buf, err = aa.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	hexEqual(t, buf,
		`00000022 0807d8e2 c44fc82e 175e5698 b1c25324 6c9a996f c37bad29 fd59b6aa
     838b0a93 0b000013 0000000f 000d000b 6578616d 706c652e 636f6d`,
	)

	h.Reset()
	privRSA, err := rsa.GenerateKey(h, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pubRSA := privRSA.Public()
	subjectRSA, err := NewTLSSubject(tlsPSSWithSHA256, pubRSA)
	if err != nil {
		t.Fatal(err)
	}
	a = Assertion{
		Subject: subjectRSA,
		Claims: Claims{
			DNSWildcard: []string{"example.com"},
			IPv4: []net.IP{
				net.ParseIP("192.0.2.37"),
				net.ParseIP("192.0.12.0"),
				net.ParseIP("198.51.100.60"),
				net.ParseIP("203.0.113.0"),
			},
		},
	}
	buf, err = a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	hexEqual(t, buf,
		`00000112 0804010e 3082010a 02820101 00be894b 98565871 0d25fe5c fe22e582
        e93d569c 703d7a15 94461548 521986c0 57d13d85 07a9205e d192959c 669d837a
        f86b05be 04fcdec3 236bde60 31c70402 10427e0d 34cc26fb 82ce540c 6821a828
        9b7e5ab1 b83ec2d6 e633a63f 432cd7a5 96dba7f0 22ca414a 25c71997 40b2cb1b
        27ddfa1b c8281b99 d1e7f46c 2adfe9c4 33f4bdea 95867f14 aba90697 30b74e3d
        1ef9bc47 6a3b3d14 b7f93890 04364165 2511206c 2066c7f5 54607199 f8773c32
        892ccc4c 4aa515a6 3b7b4d6f 2a39c696 cd76515a bb40c1dc 48b09d02 f1572ffd
        95c1e7b8 b7a3b271 f9ea093a 6778db60 e90afd82 ac0ccfed fb9c4755 ded3d328
        0bd93f3a f1432b68 85638170 194d239a 3b020301 00010029 0001000f 000d000b
        6578616d 706c652e 636f6d00 02001200 10c00002 25c0000c 00c63364 3ccb0071
        00`,
	)
	aa = a.Abridge()
	buf, err = aa.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	hexEqual(t, buf,
		`00000022 0804e892 19d40f35 4915b861 c67ffea3 3e2c8af4 efa9b5cd c751bc12
        6449a190 425d0029 0001000f 000d000b 6578616d 706c652e 636f6d00 02001200
        10c00002 25c0000c 00c63364 3ccb0071 00`,
	)

	// TODO ecdsa
}

func TestClaimsParsing(t *testing.T) {
	for _, tc := range []Claims{
		Claims{
			DNS: []string{"example.com"},
		},
		Claims{
			DNSWildcard: []string{"example.com"},
		},
		Claims{
			IPv4: []net.IP{net.ParseIP("192.0.2.37")},
		},
		Claims{
			IPv6: []net.IP{net.ParseIP("::1")},
		},
		Claims{
			DNS: []string{
				"example.com",
				"b.example.com",
				"b.b.example.com",
				"ba.example.com",
				"z.example.com",
			},
			DNSWildcard: []string{
				"example.com",
				"b.example.com",
				"b.b.example.com",
				"ba.example.com",
				"z.example.com",
			},
			IPv4: []net.IP{
				net.ParseIP("192.0.2.37"),
				net.ParseIP("192.0.12.0"),
				net.ParseIP("198.51.100.60"),
				net.ParseIP("203.0.113.0"),
			},
			IPv6: []net.IP{
				net.ParseIP("::1"),
			},
		},
	} {
		buf, err := tc.MarshalBinary()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var tc2 Claims
		err = tc2.UnmarshalBinary(buf)
		if err != nil {
			t.Fatalf("Unmarshal: %v %v", buf, err)
		}

		ptc, _ := json.Marshal(tc)
		ptc2, _ := json.Marshal(tc2)

		if !bytes.Equal(ptc, ptc2) {
			t.Fatalf("%v ≠ %v", tc, tc2)
		}
	}
}
