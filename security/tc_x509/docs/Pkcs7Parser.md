# PKCS7 parser

The parser named `PKCS7` reads PKCS #7 bundles, the `.p7b` or `.p7c` files a CA gives its chain
in: a `ContentInfo` of `SignedData` with no content and no signers, carrying certificates and
sometimes CRLs. It takes the values of its type out of each bundle and gives them one per call,
as Bouncy Castle's `X509CertificateParser` and `X509CrlParser` do:

| Type | Taken from the SignedData |
|---|---|
| certificates | the X.509 certificates of `certificates` |
| CRLs | the CRLs of `crls` |
| attribute certificates | the version 2 attribute certificates of `certificates` |

Other entries, the obsolete extended certificates and formats of other kinds, are passed over.

## Reading a bundle

```rust
use std::fs::File;
use std::io::BufReader;

use tc_x509::{DefaultX509OperatorBuilder, X509OperatorBuilder};

let operator = DefaultX509OperatorBuilder::default().build();

// The chain of the bundle, one certificate at a time
let mut parser = operator.certificate_parser().get_by_name("PKCS7")?;
let mut file = BufReader::new(File::open("chain.p7b")?);
while let Some(certificate) = parser.parse(&mut file)? {
    println!("{}", certificate.subject());
}

// Its CRLs, from the same file
let mut parser = operator.crl_parser().get_by_name("PKCS7")?;
let mut file = BufReader::new(File::open("chain.p7b")?);
while let Some(crl) = parser.parse(&mut file)? {
    println!("CRL of {}", crl.issuer());
}
```

## Using it

- The parser keeps the values of a bundle it has not given yet, and reads the next bundle once
  they are given; a bundle with none of the type is passed over. A source takes a parser of its
  own.
- The signers of the bundle are not verified, as a bundle has none; the certificates in it are
  checked as any others are.
- A `ContentInfo` of another content type is `Asn1`, as is a DER certificate given to it. Input
  that ends inside a bundle is `Io`.
- The bundle is read in DER or BER. A bundle in PEM, labelled `PKCS7`, is read by `AUTO`.
