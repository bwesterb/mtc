Merkle Tree Certificates for TLS
================================

🚨 Merkle Tree Certificates (**MTC**) is a moving target.

Implementation of [Merkle Tree Certificates for TLS](
    https://davidben.github.io/merkle-tree-certs/draft-davidben-tls-merkle-tree-certs.html)
    in Go. This contains a Certification Authority (CA), Mirror, and
    code to verify certificates.
This does not contain integration with TLS (yet) or the ACME bits (yet).
At the moment we differ from `-04` and `main` branch of the specification,
    by including some [unmerged PRs](https://github.com/davidben/merkle-tree-certs/pulls).

Demo
----

For a proper introduction and motivation, check out the [draft specification](
    https://davidben.github.io/merkle-tree-certs/draft-davidben-tls-merkle-tree-certs.html)
and [David's TLS working group presentation at IETF116](
    https://youtu.be/u_sFyz4F7dc?si=inG4bgBwKLzrBuvY&t=2566).

Merkle Tree Certificates is an **optimisation** to the WebPKI (including
[Certificate Transparency](https://certificate.transparency.dev))
motivated by the [large sizes](
    https://dadrian.io/blog/posts/pqc-signatures-2024/) of
[typical post-quantum signatures and public keys](
    https://blog.cloudflare.com/another-look-at-pq-signatures/),
to reduce the number of keys and signatures required for the common case where

 1. Certificate issuance does not have to be immediate. For instance, because
    a certificate can be requested ahead of time for an existing domain
    by an [ACME client](https://acmeclients.com)
    like [certbot](https://certbot.eff.org).

 2. The relying party (eg. browser) has a trusted update mechanism.
    There are also several ways to use MTC without trusted update mechanism,
    with various trade-offs: see the [Relying Party Policy](
    https://davidben.github.io/merkle-tree-certs/draft-davidben-tls-merkle-tree-certs.html#name-relying-party-policy)
    section of the specification.

If we're not in this case (which is estimated to be
[less than 0.1%](https://www.youtube.com/watch?v=f8unMB2Qjho) of the time),
then we fall back to regular X.509 certificates.

### Intermezzo: `mtc` commandline tool

To play around with MTC, you can install the `mtc` commandline tool:

```
$ go install github.com/bwesterb/mtc/cmd/mtc@v0.1.2
```

### Assertions

In MTC CAs certify **assertions**, which bind a **subject** to a **claim**.
An informal example of an assertion is:

> For TLS, you can trust the P-256 public key `a02342ff2…23ef`
> when visiting `example.com` or `198.51.100.60`.

The first part (TLS and the public key) is the *subject*, and the
latter (domain and IP) are the *claim*.
Roughly, an assertion is like a certificate without the signature.

You can create a request for an assertion to be signed with the
`mtc new-assertion-request` command. First, let's quickly create
a P-256 public key to play with.

```
$ openssl ecparam -name prime256v1 -genkey -out p256.priv
$ openssl ec -in p256.priv -pubout -out p256.pub
```

Now we create an assertion that this P-256 public key should
be valid for `example.com` and `198.51.100.60`, and write it to
the `my-asr`.

```
$ mtc new-assertion-request --tls-pem p256.pub --dns example.com --ip4 198.51.100.60 -o my-asr
```

Let's check it using `mtc inspect`:

```
$ mtc inspect assertion-request my-asr
checksum         2024bdbffe399acca37d299a03c047aa33ef596ae471c17698a0566d00951bd9
not_after        unset
subject_type     TLS
signature_scheme p256
public_key_hash  20b57b9c55dab26db14fb6cc801b7d7294cbf448abb1196e1ffc19d73013498a
dns              [example.com]
ip4              [198.51.100.60]
evidence-list (0 entries)
```

An assertion request can contain two bits of extra information besides
the assertion itself. First is a `not_after` field that limits
the validity of the assertion when published.
The second is optional "evidence" that's published alongside the
assertions. In the future this could for instance be used for
serialized DNSSEC proofs.

We can also create an assertion request derived from an existing X.509
certificate at a TLS server using the `-X` flag:

```
$ mtc new-assertion-request -X example.com:443 | mtc inspect assertion-request
checksum         015d4da06412b4e48f8d93bcbe7bbf43c4684579322cbfbc88d8b653bb2f7e51
not_after        unset
subject_type     TLS
signature_scheme p256
public_key_hash  8d566a5407ab85b413925911c4ce6b13013516006fa8568bf2ec58b9abe04af1
dns              [example.com]
dns_wildcard     [example.com]
evidence-list (1 entries)
umbilical
 certificate 0
  subject    CN=*.example.com,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
  issuer     CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1,O=DigiCert Inc,C=US
  serial_no  ad893bafa68b0b7fb7a404f06ecaf9a
  not_before 2025-01-15 00:00:00 +0000 UTC
  not_after  2026-01-15 23:59:59 +0000 UTC
 certificate 1
  subject    CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1,O=DigiCert Inc,C=US
  issuer     CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US
  serial_no  b00e92d4d6d731fca3059c7cb1e1886
  not_before 2021-04-14 00:00:00 +0000 UTC
  not_after  2031-04-13 23:59:59 +0000 UTC
```

### Batches, merkle trees and signed validity windows

An MTCA doesn't give you a certificate for an assertion request immediately.
Instead, assertions are queued and issued in **batches** with a fixed rhythm,
for instance a batch is issued once every hour.
All assertions in a single batch by default are valid for the same period of
time, the **validity window**, which is, for instance, two weeks.
The CA publishes these batches publicly over HTTP.

For each batch, the CA computes a [Merkle tree](
    https://en.wikipedia.org/wiki/Merkle_tree).
This condenses all the assertions in that batch into a single **tree head** hash.
For every batch, the CA signs that tree head together with all the tree heads
of the currently valid batches. This signature, together with those
signed tree heads is called the **signed validity window** for that batch,
which is published alongside the assertions.

### Creating a CA

Let's create an MTC CA.

```
$ mtc ca new --batch-duration 5m --lifetime 1h 62253.12.15 ca.example.com/path
```

This creates a new MTC CA in the current working directory. It's configured
to issue a batch every 5 minutes, and for each batch to be valid for an hour.
For a real CA we'd want batch durations in the order of an hour,
and a lifetime of a week or two. In this demo we shorten things a bit, so
we don't have to wait too long.

The CA is configured to be hosted at `https://ca.example.com/path` and
to be identified by the [trust anchor identifier](
    https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids/) 62253.12.15.
You can get your own by requesting a [private enterprise number here](
    https://www.iana.org/assignments/enterprise-numbers/).

Let's have a look at the files created:

```
$ find .
.
./signing.key
./www
./www/mtc
./www/mtc/v04b
./www/mtc/v04b/ca-params
./www/mtc/v04b/batches
./queue
./tmp
```

The `signing.key` file contains the private key of the keypair used by the CA.

The `www` folder contains the files that have to be served
at `https://ca.example.com/path`. At the moment, the only file of interest
is `ca-params`, which contains the information about the CA:

```
$ mtc inspect ca-params www/mtc/v04b/ca-params
issuer                 62253.12.15
start_time             1745420554 2025-04-23 15:02:34 +0000 UTC
batch_duration         300        5m0s
life_time              3600       1h0m0s
storage_window_size    24         2h0m0s
validity_window_size   12
server_prefix          ca.example.com/path
public_key fingerprint ml-dsa-87:84489bcb42b411a85d163ae95e7deb92b106a75840819a985e44d0e01ae3238e
```

The `batches` folder is empty, because there are no batches issued yet.

The `queue` file contains the assertion requests that will be fulfilled
during the next issuance.

### Issuing our first batch

Let's issue our first assertion. We can read the assertion request from disk we've
created earlier with `mtc new-assertion-request`:

```
$ mtc ca queue -i my-asr 
$ mtc ca show-queue
not_after        2025-04-23 16:02:33 +0000 UTC
subject_type     TLS
signature_scheme p256
public_key_hash  20b57b9c55dab26db14fb6cc801b7d7294cbf448abb1196e1ffc19d73013498a
dns              [example.com]
ip4              [198.51.100.60]
evidence-list (0 entries)

Total number of assertion requests in queue: 1
```

We can also queue an assertion request ad hoc:

```
$ mtc ca queue --tls-pem p256.pub -d other.example.com -d second.example.com
$ mtc ca show-queue | tail -n 10
not_after        2025-04-23 16:02:33 +0000 UTC
subject_type     TLS
signature_scheme p256
public_key_hash  20b57b9c55dab26db14fb6cc801b7d7294cbf448abb1196e1ffc19d73013498a
dns              [example.com]
ip4              [198.51.100.60]
evidence-list (0 entries)

Total number of assertion requests in queue: 2
```

Let's issue our first batch.

```
$ mtc ca issue
2025/04/23 17:05:20 INFO Starting issuance time=2025-04-23T15:05:20.664Z
2025/04/23 17:05:20 INFO Current state expectedStored=0 expectedActive=0 existingBatches=⌀
2025/04/23 17:05:20 INFO To issue batches=0
```

And let's check:

```
$ find .
.
./signing.key
./www
./www/mtc
./www/mtc/v04b
./www/mtc/v04b/ca-params
./www/mtc/v04b/batches
./www/mtc/v04b/batches/0
./www/mtc/v04b/batches/0/validity-window
./www/mtc/v04b/batches/0/tree
./www/mtc/v04b/batches/0/entries
./www/mtc/v04b/batches/0/evidence
./www/mtc/v04b/batches/0/index
./www/mtc/v04b/batches/latest
./queue
./tmp
```

We see batch `0` has been created. `latest` is a symlink to to `0`.

Now, let's have a look at the batch. The `entries` file is essentially
the list of assertions: the difference between a regular assertion
and an entry is that with an entry, the public key has been replaced
by the hash of the public key.

```
$ mtc inspect entries www/mtc/v04b/batches/0/entries
key              0b65c8a5f69e88fd1eb58dff4d317f6173bd31773e14d99ace88a2aa7062fdd9
not_after        2025-04-23 16:02:33 +0000 UTC
subject_type     TLS
signature_scheme p256
public_key_hash  20b57b9c55dab26db14fb6cc801b7d7294cbf448abb1196e1ffc19d73013498a
dns              [other.example.com second.example.com]

key              78b5ccc905b693659bf6581011f8efb17fd7aedf9ca70a196a22923f560feeca
not_after        2025-04-23 16:02:33 +0000 UTC
subject_type     TLS
signature_scheme p256
public_key_hash  20b57b9c55dab26db14fb6cc801b7d7294cbf448abb1196e1ffc19d73013498a
dns              [example.com]
ip4              [198.51.100.60]

Total number of entries: 2
```

The `validity-window` is the signed validity window: the tree heads of
the currently valid batches:

```
$ mtc inspect -ca-params www/mtc/v04b/ca-params validity-window www/mtc/v04b/batches/0/validity-window               
signature       ✅
batch_number    0
tree_heads[0]   043bc6b0e49a085f2370b2e0f0876d154c2e8d8fe049077dbad118a363580345
tree_heads[-1]  a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-2]  a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-3]  a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-4]  a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-5]  a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-6]  a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-7]  a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-8]  a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-9]  a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-10] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-11] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
```

We need to pass the `ca-params` file to be able to parse the file, and
check the signature therein. (As not all previous batches exist, they use
the placeholder value for an empty tree.)

The `tree` file contains the Merkle tree.

```
$ mtc inspect tree www/mtc/v04b/batches/0/tree 
number of leaves 2
number of nodes  3
tree head        043bc6b0e49a085f2370b2e0f0876d154c2e8d8fe049077dbad118a363580345
```

The `evidence` file contains the optional evidence that can be provided
with the assertion request. We did not pass any, so they're empty:

```
$ mtc inspect evidence www/mtc/v04b/batches/0/evidence
evidence-list (0 entries)

evidence-list (0 entries)

Total number of evidence lists: 2
```

Finally, the `index` file allows a quick lookup in `entries` (and `evidence`)
by key (hash of the assertion):

```
$ mtc inspect index www/mtc/v04b/batches/0/index
                                                             key   seqno  offset
0b65c8a5f69e88fd1eb58dff4d317f6173bd31773e14d99ace88a2aa7062fdd9       0       0       0
78b5ccc905b693659bf6581011f8efb17fd7aedf9ca70a196a22923f560feeca       1      91       3

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
2025/04/23 17:12:45 INFO Starting issuance time=2025-04-23T15:12:45.869Z
2025/04/23 17:12:45 INFO Current state expectedStored=0,…,2 expectedActive=0,…,2 existingBatches=0
2025/04/23 17:12:45 INFO To issue batches=1,2
$ find .
.
./signing.key
./www
./www/mtc
./www/mtc/v04b
./www/mtc/v04b/ca-params
./www/mtc/v04b/batches
./www/mtc/v04b/batches/0
./www/mtc/v04b/batches/0/validity-window
./www/mtc/v04b/batches/0/tree
./www/mtc/v04b/batches/0/entries
./www/mtc/v04b/batches/0/evidence
./www/mtc/v04b/batches/0/latest
./www/mtc/v04b/batches/0/index
./www/mtc/v04b/batches/latest
./www/mtc/v04b/batches/1
./www/mtc/v04b/batches/1/validity-window
./www/mtc/v04b/batches/1/tree
./www/mtc/v04b/batches/1/entries
./www/mtc/v04b/batches/1/evidence
./www/mtc/v04b/batches/1/index
./www/mtc/v04b/batches/2
./www/mtc/v04b/batches/2/validity-window
./www/mtc/v04b/batches/2/tree
./www/mtc/v04b/batches/2/entries
./www/mtc/v04b/batches/2/evidence
./www/mtc/v04b/batches/2/index
./queue
./tmp
```

As we waited a bit longer, the current batch is `2`, which will contain
the queued assertions. The batch `1` in between will be empty.
Now `latest` points to `2`, and its signed validity window is more interesting.

```
$ mtc inspect -ca-params www/mtc/v04b/ca-params validity-window www/mtc/v04b/batches/1/validity-window
signature      ✅
batch_number   2
tree_heads[2]  03a95ba3c354e2b0eb4bea9b111dbc8b97e2c90b85ddcc63d4b635b16f77005d
tree_heads[1]  7ceda88ec6c8e34ecacde47588e2605fb86192b94ca96cb897fa6ff442198c8c
tree_heads[0]  043bc6b0e49a085f2370b2e0f0876d154c2e8d8fe049077dbad118a363580345
tree_heads[-1] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-2] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-3] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-4] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-5] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-6] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-7] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-8] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-9] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
```

### Creating a certificate

In MTC, a **certificate** is an assertion together with a trust anchor identifier
(to identify the CA), and an authentication path in the Merkle tree.
Let's create one for our initial assertion.

```
$ mtc ca cert -i my-asr -o my-cert
```

If we inspect the certificate, it can recompute the root from the
authentication path and CA parameters:

```
$ mtc inspect -ca-params www/mtc/v04b/ca-params cert my-cert
subject_type     TLS
signature_scheme p256
public_key_hash  20b57b9c55dab26db14fb6cc801b7d7294cbf448abb1196e1ffc19d73013498a
dns              [example.com]
ip4              [198.51.100.60]

proof_type           merkle_tree_sha256
CA TAI               62253.12.15
Batch number         0
index                1
recomputed tree head 043bc6b0e49a085f2370b2e0f0876d154c2e8d8fe049077dbad118a363580345
authentication path
 8964f010faa9e499b21917f8792b541b7b1ac19f313a5d53094c698c2edc330b
```

This is indeed the root of batch `0`, and so this certificate is valid.

### Verify certificate

To automate this, there is the `mtc verify` command that takes
a certificate, the CA parameters, and a signed validity window.

```
$ mtc verify -ca-params www/mtc/v04b/ca-params -validity-window www/mtc/v04b/batches/1/validity-window my-cert
$ echo $?
0
```

Status code 0 means verification succeeded.

For transparency, you should not get the signed validity window directly
from the CA, but rather from one or more mirrors (see below).

### Run CA as server

An Merkle Tree CA can be run just from the commandline, but it's often
more convenient to run it as a server. To start the server, run:

```
$ mtc ca serve -listen-addr localhost:8080
```

This will accept HTTP requests on `localhost:8080` and serve the static
files. It will also accept queue requests; periodically issue new batches;
and return issued certificates.

Get and inspect CA parameters.

```
$ curl -s "http://localhost:8080/mtc/v04b/ca-params" -o ca-params
$ mtc inspect ca-params ca-params
issuer                 62253.12.15
start_time             1745420554 2025-04-23 15:02:34 +0000 UTC
batch_duration         300        5m0s
life_time              3600       1h0m0s
storage_window_size    24         2h0m0s
validity_window_size   12
server_prefix          ca.example.com/path
public_key fingerprint ml-dsa-87:84489bcb42b411a85d163ae95e7deb92b106a75840819a985e44d0e01ae3238e
```

Queue up the assertion created in above.

```
$ curl -X POST "http://localhost:8080/ca/queue" --data-binary "@my-asr" -w "%{http_code}"
200
```

After it's been issued, we can get the certificate via the `/ca/cert` endpoint:

```
$ curl -X POST "http://localhost:8080/ca/cert" --data-binary "@my-asr" -o my-cert
$ mtc inspect -ca-params ca-params cert my-cert
subject_type     TLS
signature_scheme p256
public_key_hash  20b57b9c55dab26db14fb6cc801b7d7294cbf448abb1196e1ffc19d73013498a
dns              [example.com]
ip4              [198.51.100.60]

proof_type           merkle_tree_sha256
CA TAI               62253.12.15
Batch number         0
index                1
recomputed tree head 043bc6b0e49a085f2370b2e0f0876d154c2e8d8fe049077dbad118a363580345
authentication path
 8964f010faa9e499b21917f8792b541b7b1ac19f313a5d53094c698c2edc330b
```

### Mirroring a CA

We can set up a new mirror with the `mtc mirror new` command:

```
$ mtc mirror new ca.example.com/path
```

This will download the `ca-params`
from `https://ca.example.com/path/mtc/v04b/ca-params` and
set up a directory structure similar to that of a CA:

```
$ find .
.
./www
./www/mtc
./www/mtc/v04b
./www/mtc/v04b/ca-params
./www/mtc/v04b/batches
./tmp
```

To bring the mirror up to date with the CA, use the `update` command:

```
$ mtc mirror update
2025/04/24 11:54:53 INFO Current state expectedStoredRemote=0 expectedActiveRemote=0 latestRemoteBatch=0 mirroredBatches=⌀
2025/04/24 11:54:53 INFO Fetching batch=0
2025/04/24 11:54:53 INFO Next batch at the earliest in 49s
$ find .
.
./www
./www/mtc
./www/mtc/v04b
./www/mtc/v04b/ca-params
./www/mtc/v04b/batches
./www/mtc/v04b/batches/0
./www/mtc/v04b/batches/0/validity-window
./www/mtc/v04b/batches/0/tree
./www/mtc/v04b/batches/0/entries
./www/mtc/v04b/batches/0/evidence
./www/mtc/v04b/batches/latest
./tmp
```

#### Local testing

To make local testing convenient, when you use `localhost` as server prefix,
the mirror will use `http` instead of `https`. This allows a quick testing
set up as follows:

```
# Set up a CA in the ca folder
$ mtc ca -p ca new --batch-duration 5m --lifetime 1h 62253.12.15 localhost:8080
$ mtc ca -p ca queue -X example.com:443
$ mtc ca -p ca issue
$ mtc ca -p ca server -listen-addr localhost:8080 &
# Set up a mirror of the CA in the mirror folder
$ mtc mirror -p mirror new localhost:8080
$ mtc mirror -p mirror update
```
