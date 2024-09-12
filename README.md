Merkle Tree Certificates for TLS
================================

🚨 Merkle Tree Certificates (**MTC**) is a moving target.

Implementation of [Merkle Tree Certificates for TLS](
    https://davidben.github.io/merkle-tree-certs/draft-davidben-tls-merkle-tree-certs.html)

At the moment only the Certification Authority (CA) side is implemented,
and we differ from `-01` and `master` branch, by including
some [unmerged PRs](https://github.com/davidben/merkle-tree-certs/pulls).

Demo
----

For a proper introduction and motivation, check out the [draft specification](
    https://davidben.github.io/merkle-tree-certs/draft-davidben-tls-merkle-tree-certs.html)
and [David's TLS working group presentation at IETF116](
    https://youtu.be/u_sFyz4F7dc?si=inG4bgBwKLzrBuvY&t=2566).

Merkle Tree Certificates is an **optimisation** to the WebPKI (including
[Certificate Transparency](https://certificate.transparency.dev))
motivated by the large sizes of typical post-quantum signatures and public keys,
to reduce the number of keys and signatures
required for the common case where

 1. Certificate issuance does not have to be immediate. For instance, because
    a certificate can be requested ahead of time for an existing domain
    by an [ACME client](https://acmeclients.com)
    like [certbot](https://certbot.eff.org).

 2. The relying party (eg. browser) has a trusted update mechanism.
    There are also several ways to use MTC without trusted update mechanism,
    with various trade-offs: see the *Transparency Services* section
    of the spec.

MTC does not aim to replace the full WebPKI, but is a first meaningful step
for improvement.

### Intermezzo: `mtc` commandline tool

To play around with MTC, you can install the `mtc` commandline tool:

```
$ go install github.com/bwesterb/mtc/cmd/mtc@v0.1.1
```

### Assertions

In MTC CAs certify **assertions**, which bind a **subject** to a **claim**.
An informal example of an assertion is:

> For TLS, you can trust the P-256 public key `a02342ff2…23ef`
> when visiting `example.com` or `198.51.100.60`.

The first part (TLS and the public key) is the *subject*, and the
latter (domain and IP) are the *claim*.
Roughly, an assertion is like a certificate without the signature.

To create an assertion, you can use the `mtc new-assertion` command.
First, let's quickly create a P-256 public key to play with.

```
$ openssl ecparam -name prime256v1 -genkey -out p256.priv
$ openssl ec -in p256.priv -pubout -out p256.pub
```

Now we create an assertion that this P-256 public key should
be valid for `example.com` and `198.51.100.60`, and write it to
the `my-assertion`.

```
$ mtc new-assertion --tls-pem p256.pub --dns example.com --ip4 198.51.100.60 -o my-assertion
checksum: 14bc907eafd02d5be8b8cc319d87ad5afe9266a6910a18cbdcbfcee1b7af696a
```

Let's check it using `mtc inspect`:

```
$ mtc inspect assertion my-assertion
subject_type     TLS
signature_scheme p256
public_key_hash  a02a1758e4c9d6511dc02f59301b9f29e41762d3d769c87a22333497984a41ef
dns              [example.com]
ip4              [198.51.100.60]
```

### Batches, merkle trees and signed validity windows

An MTC CA doesn't give you a certificate for an assertion immediately. Instead,
assertions are queued and issued in **batches** with a fixed rhythm,
for instance a batch is issused once every hour.
All assertions in a single batch are valid for the same period of time,
the **validity window**, which is, for instance, two weeks.
The CA publishes these batches publicly over HTTP.

For each batch, the CA computes a [Merkle tree](
    https://en.wikipedia.org/wiki/Merkle_tree).
This condenses all the assertions in that batch into a single **root** hash.
For every batch, the CA signs that root together with all the roots
    of the currently valid batches. This signature, together with those
    signed roots is called the **signed validity window** for that batch,
    which is published alongside the assertions.

### Creating a CA

Let's create an MTC CA.

```
$ mtc ca new --batch-duration 5m --lifetime 1h 1230.12.15 ca.example.com/path
```

This creates a new MTC CA called `my-mtc-ca`, and puts the data in the
current working directory. A batch is issued every 5 minutes, and
each batch is valid for one hour.

Let's have a look at the files created:

```
$ find .
.
./signing.key
./www
./www/mtc
./www/mtc/v1
./www/mtc/v1/ca-params
./www/mtc/v1/batches
./queue
./tmp
```

The `signing.key` file contains the private key of the keypair used by the CA.

The `www` folder contains the files that have to be served
at `https://ca.example.com/path`. At the moment, the only file of interest
is `ca-params`, which contains the information about the CA:

```
$ mtc inspect ca-params www/mtc/v1/ca-params
issuer_id              my-mtc-ca
start_time             1705677477 2024-01-19 16:17:57 +0100 CET
batch_duration         300        5m0s
life_time              3600       1h0m0s
storage_window_size    24         2h0m0s
validity_window_size   12
http_server            ca.example.com/path
public_key fingerprint dilithium5:85b5a617ef109e0a8d68a094c8b969f622ac4096c513fa0acd169c231ce2fad5
```

The `batches` folder is empty, because there are no batches issued yet.

The `queue` file contains the assertions that will be issued.

### Issuing our first batch

Let's issue our first assertion. We can read the assertion from disk we've
created earlier with `mtc new-assertion`:

```
$ mtc ca queue -i my-assertion 
$ mtc ca show-queue
checksum         14bc907eafd02d5be8b8cc319d87ad5afe9266a6910a18cbdcbfcee1b7af696a
subject_type     TLS
signature_scheme p256
public_key_hash  a02a1758e4c9d6511dc02f59301b9f29e41762d3d769c87a22333497984a41ef
dns              [example.com]
ip4              [198.51.100.60]

Total number of assertions in queue: 1
```

(We can pass the checksum from `new-assertion` with `--checksum` to make sure
the assertion wasn't corrupted.)

We can also queue an assertion ad hoc:

```
$ mtc ca queue --tls-pem p256.pub -d other.example.com -d second.example.com
$ mtc ca show-queue | tail -n 8

checksum         fbdea936ae7795a3fa01d44230daba351d7480eceadd086ba32938ebc88a5458
subject_type     TLS
signature_scheme p256
public_key_hash  a02a1758e4c9d6511dc02f59301b9f29e41762d3d769c87a22333497984a41ef
dns              [other.example.com second.example.com]

Total number of assertions in queue: 2
```

Let's issue our first batch.

```
$ mtc ca issue   
2024/01/19 16:27:31 INFO Starting issuance time=2024-01-19T16:27:31.841+01:00
2024/01/19 16:27:31 INFO Current state expectedStored=0 expectedActive=0 existingBatches=⌀
2024/01/19 16:27:31 INFO To issue batches=0
```

And let's check:

```
$ find .
.
./signing.key
./www
./www/mtc
./www/mtc/v1
./www/mtc/v1/ca-params
./www/mtc/v1/batches
./www/mtc/v1/batches/0
./www/mtc/v1/batches/0/tree
./www/mtc/v1/batches/0/abridged-assertions
./www/mtc/v1/batches/0/signed-validity-window
./www/mtc/v1/batches/0/index
./www/mtc/v1/batches/latest
./queue
./tmp
```

We see a `0` batch has been created. `latest` is a symlink to `0`.

The `abridged-assertions` is essentially the list of assertions:
the difference between a regular and abridged assertion,
is that with an abridged assertion, the public key has been replaced
by the hash of the public key.

```
$ mtc inspect abridged-assertions www/mtc/v1/batches/0/abridged-assertions
key              28b2216e7905ab48d5444f5b7ebf3d2386bc0444c9721fff77b0b313e734dab4
subject_type     TLS
signature_scheme p256
public_key_hash  a02a1758e4c9d6511dc02f59301b9f29e41762d3d769c87a22333497984a41ef
dns              [example.com]
ip4              [198.51.100.60]

key              80944a1728bc7b4cd7e583c6b24a5f413ba50b7ef5ba9d214e26c1a1974f0a19
subject_type     TLS
signature_scheme p256
public_key_hash  a02a1758e4c9d6511dc02f59301b9f29e41762d3d769c87a22333497984a41ef
dns              [other.example.com second.example.com]

Total number of abridged assertions: 2
```

The `signed-validity-window` is the signed validity window: the roots of
the currently valid batches:

```
$ mtc inspect -ca-params www/mtc/v1/ca-params signed-validity-window www/mtc/v1/batches/0/signed-validity-window 
signature       ✅
batch_number    0
tree_heads[-11] f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-10] f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-9]  f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-8]  f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-7]  f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-6]  f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-5]  f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-4]  f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-3]  f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-2]  f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-1]  f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[0]   c005dcdb53c4e41befcf3a294b815d8b8aa0a260e9f10bfd4e4cb52eb3724aa3
```

We need to pass the `ca-params` file to be able to parse the file, and
check the signature therein. (As this is the first batch, the previous batches
contain a placeholder value.)

The `tree` file contains the Merkle tree.

```
$ mtc inspect tree www/mtc/v1/batches/0/tree       
number of leaves 2
number of nodes  3
root             c005dcdb53c4e41befcf3a294b815d8b8aa0a260e9f10bfd4e4cb52eb3724aa3
```

Finally, the `index` file allows a quick lookup in `abridged-assertions`
by key (hash of the assertion):

```
$ mtc inspect index www/mtc/v1/batches/0/index
                                                             key   seqno  offset
28b2216e7905ab48d5444f5b7ebf3d2386bc0444c9721fff77b0b313e734dab4       0       0
80944a1728bc7b4cd7e583c6b24a5f413ba50b7ef5ba9d214e26c1a1974f0a19       1      69

total number of entries: 2
```

### Issuing more batches

As we just issued a new batch, we need to wait a while before the
next batch is ready to issue.

Let's queue some more assertions, wait a bit, and issue a new batch.

```
$ mtc ca queue --tls-pem p256.pub -d 1.example.com
$ mtc ca queue --tls-pem p256.pub -d 2.example.com
$ mtc ca queue --tls-pem p256.pub -d 3.example.com
$ mtc ca issue
2024/01/19 16:33:57 INFO Starting issuance time=2024-01-19T16:33:57.860+01:00
2024/01/19 16:33:57 INFO Current state expectedStored=0,…,2 expectedActive=0,…,2 existingBatches=0
2024/01/19 16:33:57 INFO To issue batches=1,2
$ find .
.
./signing.key
./www
./www/mtc
./www/mtc/v1
./www/mtc/v1/ca-params
./www/mtc/v1/batches
./www/mtc/v1/batches/0
./www/mtc/v1/batches/0/tree
./www/mtc/v1/batches/0/abridged-assertions
./www/mtc/v1/batches/0/signed-validity-window
./www/mtc/v1/batches/0/index
./www/mtc/v1/batches/latest
./www/mtc/v1/batches/1
./www/mtc/v1/batches/1/tree
./www/mtc/v1/batches/1/abridged-assertions
./www/mtc/v1/batches/1/signed-validity-window
./www/mtc/v1/batches/1/index
./www/mtc/v1/batches/2
./www/mtc/v1/batches/2/tree
./www/mtc/v1/batches/2/abridged-assertions
./www/mtc/v1/batches/2/signed-validity-window
./www/mtc/v1/batches/2/index
./queue
./tmp
```

As we waited a bit longer, the current batch is `2`, which will contain
the queued assertions. The batch `1` in between will be empty.

Now `latest` points to `2`, and its signed validity window is more interesting.

```
$ mtc inspect -ca-params www/mtc/v1/ca-params signed-validity-window www/mtc/v1/batches/2/signed-validity-window
signature      ✅
batch_number   2
tree_heads[-9] f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-8] f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-7] f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-6] f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-5] f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-4] f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-3] f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-2] f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[-1] f2f65b0486c8cad3876475c9c509afdf3f51dc073b1d2d2d261ff9883d63f98e
tree_heads[0]  c005dcdb53c4e41befcf3a294b815d8b8aa0a260e9f10bfd4e4cb52eb3724aa3
tree_heads[1]  98a421741cf06a19b56d7b52436f686885bd798611426f638ffcdb6b5a65c42c
tree_heads[2]  ab3cb1262fc084be0447c2b3d175d63f6ec2782dcc1443888b12f685976093d5
```

### Creating a certificate

In MTC, a **certificate** is an assertion, together with the batch number,
`issuer_id` of the CA, and an authentication path in the Merkle tree.
Let's create one for our initial assertion.

```
$ mtc ca cert -i my-assertion -o my-cert
$ mtc inspect cert my-cert
subject_type     TLS
signature_scheme p256
public_key_hash  a02a1758e4c9d6511dc02f59301b9f29e41762d3d769c87a22333497984a41ef
dns              [example.com]
ip4              [198.51.100.60]

proof_type merkle_tree_sha256
issuer_id  my-mtc-ca
batch      0
index      0
authentication path
 00b17df8d909fd3e77005486a16ca00fdc9af38f92a23351359fd420d9f2ef78
```

If we provide the `ca-params` to `mtc inspect`, it can recompute the root
from the authentication path:

```
$ mtc inspect -ca-params www/mtc/v1/ca-params cert my-cert
[…]
batch           0
index           0
recomputed root c005dcdb53c4e41befcf3a294b815d8b8aa0a260e9f10bfd4e4cb52eb3724aa3
authentication path
 00b17df8d909fd3e77005486a16ca00fdc9af38f92a23351359fd420d9f2ef78
```

This is indeed the root of the `0`th batch, and so this certificate is valid.

