module github.com/bwesterb/mtc/cmd/mtc

go 1.21.3

require (
	github.com/bwesterb/mtc/ca v0.0.0-00010101000000-000000000000
	github.com/urfave/cli/v2 v2.25.7
)

require (
	github.com/bwesterb/mtc v0.0.0-20231024183253-c77f499a3575 // indirect
	github.com/cloudflare/circl v1.3.5 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/nightlyone/lockfile v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

replace github.com/bwesterb/mtc => ../../

replace github.com/bwesterb/mtc/ca => ../../ca
