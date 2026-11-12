# DER parser

The parser named `DER` reads values encoded one after another in DER, or in BER, as `decode`
accepts it: a file of one certificate, or a stream of several. It reads one value per call and
nothing past it, so what follows stays in the stream for the next call.

## Reading certificates

```rust
use std::fs::File;
use std::io::BufReader;

use tc_x509::{DefaultX509OperatorBuilder, X509OperatorBuilder};

let operator = DefaultX509OperatorBuilder::default().build();
let mut parser = operator.certificate_parser().get_by_name("DER")?;

let mut file = BufReader::new(File::open("certificates.der")?);
while let Some(certificate) = parser.parse(&mut file)? {
    println!("{}", certificate.subject());
}
```

`crl_parser` and `attribute_certificate_parser` give the DER parsers of CRLs and of attribute
certificates, read the same way.

## Using it

- Each value is read as `decode_from` reads it: its header first, then its contents, within the
  default limits of `tc_asn1`, so a length a peer claims is checked before anything is held for
  it.
- A value that is not one of the type, such as a CRL given to the certificate parser, is
  `Asn1`, carrying the `Asn1Error`. Input that ends inside a value is `Io`.
- Empty input, or input that ends between values, gives `None`.
- The parser reads one octet at a time while it reads a header, so a file or a socket is best
  read through a `BufReader`.
- A PEM file is refused, since its first octet is not a SEQUENCE; ask for `PEM` or `AUTO`.
