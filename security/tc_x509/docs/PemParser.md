# PEM parser

The parser named `PEM` reads PEM blocks one after another, the text between
`-----BEGIN label-----` and `-----END label-----`, takes those whose label is one of its type's
and passes over the others, as Bouncy Castle's `PemParser` does:

| Type | Labels |
|---|---|
| certificates | `CERTIFICATE`, `X509 CERTIFICATE` |
| CRLs | `X509 CRL`, `CRL` |
| attribute certificates | `ATTRIBUTE CERTIFICATE` |

A file that holds a chain, a CRL and a key in PEM can be given to each parser, and each takes its
own blocks.

## Reading certificates

```rust
use std::fs::File;
use std::io::BufReader;

use tc_x509::{DefaultX509OperatorBuilder, X509OperatorBuilder};

let operator = DefaultX509OperatorBuilder::default().build();

// The certificates of a chain, passing over a CRL or a key among them
let mut parser = operator.certificate_parser().get_by_name("PEM")?;
let mut file = BufReader::new(File::open("chain.pem")?);
while let Some(certificate) = parser.parse(&mut file)? {
    println!("{}", certificate.subject());
}

// The CRLs of the same file
let mut parser = operator.crl_parser().get_by_name("PEM")?;
let mut file = BufReader::new(File::open("chain.pem")?);
while let Some(crl) = parser.parse(&mut file)? {
    println!("CRL of {}", crl.issuer());
}
```

## Using it

- The blocks are read with `tc_pem`'s `PemReader`; text before a `BEGIN` line is passed over,
  and lines may end in LF or CRLF.
- A block is read one octet at a time, so nothing past it is read, and a file is best read
  through a `BufReader`.
- A block whose content is not base64, or whose frame is broken, is `Io`; one whose content does
  not decode as the type is `Asn1`.
- A block labelled `PKCS7` is passed over, as any label not of the type; `AUTO` reads it as a
  bundle.
- The end of the input, with or without blocks of other labels before it, gives `None`.
