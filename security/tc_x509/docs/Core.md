# Core types

## X509Certificate

A certificate as received. It gives its fields, `serial_number`, `issuer`, `subject`,
`not_before`, `not_after`, `subject_public_key_info`, `extensions` and the rest, and the octets
that were signed are kept as they came, so the signature stays valid when it is written back.

- **Its public key**: `subject_public_key_info` is the key as the certificate holds it, its
  algorithm and its octets; the operator's `spki().decode` turns it into a key the algorithms
  take, to verify with, encrypt to or agree with.
- **Checking it**: `is_valid_at` tells whether a time falls within its validity, `verify` checks
  its signature with the key of its issuer, and the issuer's CRL tells whether it is revoked.
  Building the chain from a certificate up to a CA one trusts, and the checks of RFC 5280 along
  it, are not part of this crate.

[X509Certificate](X509Certificate.md) has every method and an example.

## X509Crl

A certificate revocation list as received. It gives its `issuer`, `this_update`, `next_update`
and its entries, each an `X509CrlEntry`, and tells whether a certificate `is_revoked`: listed
under its issuer and serial number, with any reason but `removeFromCRL`. The first lookup builds
an index of serial numbers, so a CRL of many entries answers each certificate with a hash.

A CRL is only as good as the key it verifies with, so its signature is checked with the key of
its issuer before it is trusted.

[X509Crl](X509Crl.md) has every method, the entries, indirect CRLs and an example.

## X509AttributeCertificate

Binds attributes, such as roles, to the holder of a public-key certificate, issued and signed by
an attribute authority. It gives its `holder`, `issuer`, validity and `attributes`, and verifies
its signature as a certificate does.

## X509Operator

Where the algorithms are, found by name. `DefaultX509OperatorBuilder` builds one, with the
algorithms of `tc_algo` unless `set_algo` gives others. It gives:

- `key_pair_generator`, for new key pairs, such as `"RSA"`;
- `spki`, which turns a public key into the `SubjectPublicKeyInfo` a certificate holds, and back;
- `signature_factory`, which signs with a private key under an algorithm such as
  `"SHA-256withRSA"`, for the generators;
- `verifier_factory` and `verifier_factory_provider`, which verify with a public key, the latter
  taking the algorithm from what is verified;
- `certificate_parser`, `crl_parser` and `attribute_certificate_parser`, which read files by the
  name of their format.

The builder registers more with `reg_spki`, `reg_signer` and `reg_certificate_parser` and its
like; one registered later is found first, so it can take over a built-in one.
