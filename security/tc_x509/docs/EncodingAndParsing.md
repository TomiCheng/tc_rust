# Encoding, decoding and parsing

`X509Certificate`, `X509Crl` and `X509AttributeCertificate` read and write their DER themselves.
Files in other formats, PEM or PKCS #7, and files whose format is not known are read with the
parsers of an `X509Operator`.

## DER in and out

| Method | Does |
|---|---|
| `encode()` | the DER, as a `Vec<u8>` |
| `encode_to(&mut Write)` | the DER, written to a file or a socket |
| `decode(&[u8])` | one value, the whole slice |
| `decode_from(Read)` | one value from a stream, and nothing past it; `None` at the end |

`decode` and `decode_from` accept BER as well as DER, and keep the signed octets as they came, so
the signature stays valid when the value is encoded again. `decode_from` reads exactly one value,
so a stream of several is read with a loop, and what follows stays in the stream; a file or a
socket is best read through a `BufReader`.

There is no writer for other formats: a PEM block or a PKCS #7 bundle is built from the DER of
`encode`, with `tc_pem`'s `PemWriter` or `tc_asn1_pkcs`'s `SignedData`.

## Parsers

A parser reads values of one type from a `Read` in one format, one value per call, `None` at the
end, and reads nothing past the value it gives. `certificate_parser`, `crl_parser` and
`attribute_certificate_parser` of the operator find one by the name of its format, in any case:

- [DER](DerParser.md): values one after another, in DER or BER.
- [PEM](PemParser.md): the PEM blocks labelled for the type, passing over the others.
- [PKCS7](Pkcs7Parser.md): the certificates, CRLs or attribute certificates of a PKCS #7 bundle,
  a `.p7b`.
- `AUTO`: any of these, told from the first octet of each value: text is PEM, where a block
  labelled `PKCS7` is a bundle; a SEQUENCE whose first field is an OBJECT IDENTIFIER is a PKCS #7
  bundle; any other SEQUENCE is one DER value.

The same file can be given to the parsers of each type, and each takes its own values from it. A
parser keeps state between calls, the values of a bundle not yet given, so each source takes a
parser of its own. A caller who knows the format names it, so that a file in another one is
refused; one who does not asks for `AUTO`. A name no format has is `UnknownParser`.

## A format of one's own

A parser is a type that implements `Parser<T>`, made by a `ParserEntry<T>` that gives its name
and makes a new parser for each source. The builder registers entries with
`reg_certificate_parser`, `reg_crl_parser` and `reg_attribute_certificate_parser`; one
registered later is found first, so it can take over a built-in name.
