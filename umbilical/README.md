Umbilical certificates
======================

For first experiments with Merkle Tree Certificates, a client may wish
that each Merkle Tree Certificate is backed by a traditional X.509
certificate (chain) issued by a trusted CA. We call this the *umbilical*
certificate/chain.

To accomedate this we allocate two new `EvidenceType`:

```
enum {
    umbilical(0),
    compressed_umbilical(1),
    (2^16-1)
} EvidenceType;
```

For `umbilical` the `info` field of an `Evidence` entry contains the
concatenated ASN.1 DER encoded X.509 certificates of the umbilical chain.

The `-from-x509-pem` (`-x`) and `-from-x509-server` (`-X`) options to
`mtc ca queue` and `mtc new-assertion-request` will automatically
add the X.509 chain as evidence to the assertion-request.

MTCA evidence policy
--------------------
By default, the MTCA will publish the evidence, but it will not check it
or demand it's present.

The MTCA can be configured to require umbilical evidence before publishing,
by setting the *evidence policy* to `umbilical`:

```
mtc ca new -evidence-policy umbilical -umbilical-roots root_store.certs  62253.12.15 ca.example.com
```

The `-umbilical-roots` flag sets the PEM encoded root certificates that
are trusted. 

Before accepting an assertion request to the queue, the MTCA will
require an umbilical chain as evidence, which verifies against one
of the umbilical roots. It will also check revocation using OCSP if available,
and falling back to CRL otherwise. CRLs are cached in `revocation-cache`.

A mirror will follow the evidence policy set by the CA. If the CA does not
have an evidence policy set, the mirror will simply copy evidence, but not
performe any checks. If the CA has umbilical evidence policy, it will
check for each entry whether the umbilical evidence is present and correct.

To ensure the mirror checks umbilical evidence, you can
pass `-evidence-policy umbilical` to `mtc mirror new`. You can also set
the umbilical roots using `-umbilical-roots`, which are otherwise blindly
copied from the CA.

Compressed umbilical
--------------------
The plain `umbilical` evidence format will lead to many duplicated
intermediate certificates. To save space, there is an alternate format
`compressed_umbilical`. Evidence with the `compressed_umbilical` type
has as `info` field the concatenation of the SHA256 hashes
of each of the original ASN.1 DER encoded X.509 certificates.

The certificates themselves are published in an `umbilical-certificates`
file in each batch. The format of the `umbilical-certificates` file
is described in `umbilical/frozencas/frozencas.go`. It basically
concatenates the certificates and adds a simple index to look up
a certificate by its SHA256 hash using interpolation search.
(`frozencas` stands for *frozen content-addressed storage* btw.)

An umbilical certificate does not have to appear in the `umbilical-certificates`
file of the batch it's used in, but must appear in one of the batches within
the window that ends at the current batch.

The mirror accepts both umbilical and compressed umbilical evidence.
When set to umbilical evidence policy, the MTCA will always use the
compressed evidence format.
