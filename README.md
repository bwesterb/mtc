Merkle Tree Certificates for TLS
================================

🚨 Merkle Tree Certificates (**MTC**) is a moving target.

Implementation of [Merkle Tree Certificates for TLS](
    https://davidben.github.io/merkle-tree-certs/draft-davidben-tls-merkle-tree-certs.html)
    in Go. This contains a Certification Authority (CA), mirror, and
    code to verify certificates.
This does not contain integration with TLS (yet) or the ACME bits.
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
$ ./mtc inspect assertion-request my-asr
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
the assertion itself. First is a `not_after` field to request to limit
the validity of the assertion when published.
The second is optional "evidence" that's published alongside the
assertions. In the future this could be used for serialized DNSSEC proofs.

### Batches, merkle trees and signed validity windows

An MTC CA doesn't give you a certificate for an assertion request immediately.
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
It is identified by the [trust anchor identifier](
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
start_time             1745415825 2025-04-23 13:43:45 +0000 UTC
batch_duration         300        5m0s
life_time              3600       1h0m0s
storage_window_size    24         2h0m0s
validity_window_size   12
server_prefix          ca.example.com/path
public_key fingerprint ml-dsa-87:52f3488ca58a51a3d8d4b5d054828e5ebcc3767a0732da374f608f766cf8bad2
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
checksum         3241885a438bd82f21d193fe7be9e87a24f5b6aac899bd780b1604da0ec39f48
not_after        2025-04-23 14:48:44 +0000 UTC
subject_type     TLS
signature_scheme p256
public_key_hash  20b57b9c55dab26db14fb6cc801b7d7294cbf448abb1196e1ffc19d73013498a
dns              [example.com]
ip4              [198.51.100.60]
evidence-list (0 entries)

Total number of assertion requests in queue: 1
```

(We can pass the checksum from `new-assertion-request` with `--checksum`
to make sure the assertion wasn't corrupted.)

We can also queue an assertion request ad hoc:

```
$ mtc ca queue --tls-pem p256.pub -d other.example.com -d second.example.com
$ mtc ca show-queue | tail -n 10
checksum         3241885a438bd82f21d193fe7be9e87a24f5b6aac899bd780b1604da0ec39f48
not_after        2025-04-23 14:48:44 +0000 UTC
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
2025/04/23 15:50:58 INFO Starting issuance time=2025-04-23T13:50:58.023Z
2025/04/23 15:50:58 INFO Current state expectedStored=0,1 expectedActive=0,1 existingBatches=⌀
2025/04/23 15:50:58 INFO To issue batches=0,1
```

And let's check:

```
$ find .
```
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
./www/mtc/v04b/batches/1
./www/mtc/v04b/batches/1/validity-window
./www/mtc/v04b/batches/1/tree
./www/mtc/v04b/batches/1/entries
./www/mtc/v04b/batches/1/evidence
./www/mtc/v04b/batches/1/index
./queue
./tmp
```

We see an `0` and `1` batch have been created. `latest` is a symlink to `1`.

Because we waited more than 5 minutes between creating the CA,
and starting issuance, both batches `0` and `1` were ready to be issued.
The assertions have been issued in batch `1` and batch `0` is empty.

Now, let's have a look at each batch. The `entries` file is essentially
the list of assertions: the difference between a regular assertion
and an entry is that with an entry, the public key has been replaced
by the hash of the public key.

```
$ mtc inspect entries www/mtc/v04b/batches/0/entries 
Total number of entries: 0
$ mtc inspect entries www/mtc/v04b/batches/1/entries
key              0b65c8a5f69e88fd1eb58dff4d317f6173bd31773e14d99ace88a2aa7062fdd9
not_after        2025-04-23 14:48:44 +0000 UTC
subject_type     TLS
signature_scheme p256
public_key_hash  20b57b9c55dab26db14fb6cc801b7d7294cbf448abb1196e1ffc19d73013498a
dns              [other.example.com second.example.com]

key              78b5ccc905b693659bf6581011f8efb17fd7aedf9ca70a196a22923f560feeca
not_after        2025-04-23 14:48:44 +0000 UTC
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
$ mtc inspect -ca-params www/mtc/v04b/ca-params validity-window www/mtc/v04b/batches/1/validity-window 
signature       ✅
batch_number    1
tree_heads[1]   074e46cfebf57e3e21bea9b8eb6f446060db668926a041aa0bc2b13e0708dd3e
tree_heads[0]   a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
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
```

We need to pass the `ca-params` file to be able to parse the file, and
check the signature therein. (As not all previous batches exist, they use
the placeholder value for an empty tree.)

The `tree` file contains the Merkle tree.

```
$ mtc inspect tree www/mtc/v04b/batches/1/tree 
number of leaves 2
number of nodes  3
tree head        074e46cfebf57e3e21bea9b8eb6f446060db668926a041aa0bc2b13e0708dd3e
```

The `evidence` file contains the optional evidence that can be provided
with the assertion request. We did not pass any, so they're empty:

```
$ mtc inspect evidence www/mtc/v04b/batches/1/evidence
evidence-list (0 entries)

evidence-list (0 entries)

Total number of evidence lists: 2
```

Finally, the `index` file allows a quick lookup in `entries` (and `evidence`)
by key (hash of the assertion):

```
$ mtc inspect index www/mtc/v04b/batches/1/index
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
2025/04/23 16:03:35 INFO Starting issuance time=2025-04-23T14:03:35.653Z
2025/04/23 16:03:35 INFO Current state expectedStored=0,…,3 expectedActive=0,…,3 existingBatches=0,1
2025/04/23 16:03:35 INFO To issue batches=2,3
$ find .
```
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
./www/mtc/v04b/batches/1
./www/mtc/v04b/batches/1/validity-window
./www/mtc/v04b/batches/1/tree
./www/mtc/v04b/batches/1/entries
./www/mtc/v04b/batches/1/evidence
./www/mtc/v04b/batches/1/index
./www/mtc/v04b/batches/3
./www/mtc/v04b/batches/3/validity-window
./www/mtc/v04b/batches/3/tree
./www/mtc/v04b/batches/3/entries
./www/mtc/v04b/batches/3/evidence
./www/mtc/v04b/batches/3/index
./www/mtc/v04b/batches/2
./www/mtc/v04b/batches/2/validity-window
./www/mtc/v04b/batches/2/tree
./www/mtc/v04b/batches/2/entries
./www/mtc/v04b/batches/2/evidence
./www/mtc/v04b/batches/2/index
./queue
./tmp
```

As we waited a bit longer (again), the current batch is `3`, which will contain
the queued assertions. The batch `2` in between will be empty.

Now `latest` points to `3`, and its signed validity window is more interesting.

```
$ mtc inspect -ca-params www/mtc/v04b/ca-params validity-window www/mtc/v04b/batches/3/validity-window
signature      ✅
batch_number   3
tree_heads[3]  73bff824738bd56b400477ead88a50c61a449c390d539412e95c763f8da1e041
tree_heads[2]  a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[1]  a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[0]  a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-1] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-2] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-3] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-4] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-5] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-6] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-7] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
tree_heads[-8] a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf
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
CA OID               62253.12.15
Batch number         1
index                1
recomputed tree head 074e46cfebf57e3e21bea9b8eb6f446060db668926a041aa0bc2b13e0708dd3e
authentication path
 e1c642c6da3e8665d83cc359e830929386b11658c55146e88e79c2c466b8cecb
```

This is indeed the root of batch `1`, and so this certificate is valid.

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
start_time             1745415825 2025-04-23 13:43:45 +0000 UTC
batch_duration         300        5m0s
life_time              3600       1h0m0s
storage_window_size    24         2h0m0s
validity_window_size   12
server_prefix          ca.example.com/path
public_key fingerprint ml-dsa-87:52f3488ca58a51a3d8d4b5d054828e5ebcc3767a0732da374f608f766cf8bad2
```

Queue up the assertion created in above.

```
$ curl -X POST "http://localhost:8080/ca/queue" --data-binary "@my-asr" -w "%{http_code}"
200
```

After it's been issued, we can get the certificate via the `/ca/cert` endpoint:

```
$ curl -X POST "http://localhost:8080/ca/cert" --data-binary "@my-assertion" -o my-cert
$ mtc inspect -ca-params ca-params cert my-cert
subject_type     TLS
signature_scheme p256
public_key_hash  20b57b9c55dab26db14fb6cc801b7d7294cbf448abb1196e1ffc19d73013498a
dns              [example.com]
ip4              [198.51.100.60]

proof_type           merkle_tree_sha256
CA OID               62253.12.15
Batch number         1
index                1
recomputed tree head 074e46cfebf57e3e21bea9b8eb6f446060db668926a041aa0bc2b13e0708dd3e
authentication path
 e1c642c6da3e8665d83cc359e830929386b11658c55146e88e79c2c466b8cecb
```
