# tc_asn1_x500

Named ASN.1 structures of the X.500 directory series: `Name`,
`RelativeDistinguishedName` and `AttributeTypeAndValue` from X.501, and
`DirectoryString` with the attribute type OIDs from X.520. X.509 certificates
only borrow these for subject and issuer, so they live apart from the
certificate crate. The crate is `no_std` + `alloc`.

Bouncy Castle counterpart:
[`crypto/src/asn1/x500/`](https://github.com/bcgit/bc-csharp/tree/7fa86379/crypto/src/asn1/x500)
plus the wire part of `x509/X509Name.cs`.

## Status

| Item | Status |
| --- | --- |
| `AttributeType`: OIDs with RFC 4514/4519 short names, lookup both ways | done |
| `DirectoryString` | done |
| `AttributeTypeAndValue`, `AttributeValue` | done |
| `RelativeDistinguishedName` | done |
| `Name` | done |
| RFC 4514 text: `Display` and `FromStr` on `Name` | done |
| Relaxed comparison (`equivalent`, RFC 5280 §7.1) | done, with RFC 4518 approximated by lowercasing and whitespace collapsing |
| Name constraints matching (prefix of RDNs) | not started; waits for the x509 extension |

`==` on every type is the strict, DER-level comparison; `equivalent` is the
relaxed one certificate path validation needs.
