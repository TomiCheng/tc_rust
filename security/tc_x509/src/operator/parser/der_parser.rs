use std::io::{self, Read};

use tc_asn1::Asn1Error;

use super::{Parser, ParserEntry};
use crate::X509Error;
use crate::cert::{X509AttributeCertificate, X509Certificate};
use crate::crl::X509Crl;

// Reads one value of its type, nothing past it
type Decode<T> = fn(&mut dyn Read) -> io::Result<Option<T>>;

// An error of decode_from: the Asn1Error it carries when the value does not decode, the I/O
// error otherwise
pub(crate) fn from_io(error: io::Error) -> X509Error {
    if error.kind() == io::ErrorKind::InvalidData
        && error
            .get_ref()
            .is_some_and(|inner| inner.downcast_ref::<Asn1Error>().is_some())
    {
        let inner = error.into_inner().expect("checked above");
        return X509Error::Asn1(*inner.downcast::<Asn1Error>().expect("checked above"));
    }
    X509Error::Io(error)
}

// The "DER" format: values encoded one after another, each read whole and decoded as BER, as
// decode reads them, since a certificate in BER is still met
pub(crate) struct DerParser<T> {
    decode: Decode<T>,
}

impl<T> Parser<T> for DerParser<T> {
    fn parse(&mut self, input: &mut dyn Read) -> Result<Option<T>, X509Error> {
        (self.decode)(input).map_err(from_io)
    }
}

pub(crate) struct DerParserEntry<T> {
    decode: Decode<T>,
}

impl DerParserEntry<X509Certificate> {
    pub(crate) fn certificates() -> Self {
        Self {
            decode: |input| X509Certificate::decode_from(input),
        }
    }
}

impl DerParserEntry<X509Crl> {
    pub(crate) fn crls() -> Self {
        Self {
            decode: |input| X509Crl::decode_from(input),
        }
    }
}

impl DerParserEntry<X509AttributeCertificate> {
    pub(crate) fn attribute_certificates() -> Self {
        Self {
            decode: |input| X509AttributeCertificate::decode_from(input),
        }
    }
}

impl<T: 'static> ParserEntry<T> for DerParserEntry<T> {
    fn name(&self) -> &str {
        "DER"
    }

    fn create(&self) -> Box<dyn Parser<T>> {
        Box::new(DerParser {
            decode: self.decode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/data/crl/{name}.der",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn the_der_parser_reads_certificates_one_after_another_then_none() {
        let mut input = data("ca");
        input.extend(data("good"));
        input.extend(data("revoked"));
        let mut source = &input[..];

        let mut parser = DerParserEntry::certificates().create();
        let mut subjects = Vec::new();
        while let Some(certificate) = parser.parse(&mut source).unwrap() {
            subjects.push(certificate.subject().to_string());
        }
        assert_eq!(subjects, ["CN=Test CA", "CN=good", "CN=revoked"]);
        assert!(parser.parse(&mut source).unwrap().is_none());
    }

    #[test]
    fn the_der_parser_reads_a_crl_and_nothing_from_empty_input() {
        let input = data("crl");
        let mut parser = DerParserEntry::crls().create();
        assert!(parser.parse(&mut &input[..]).unwrap().is_some());
        assert!(parser.parse(&mut &[][..]).unwrap().is_none());
    }

    #[test]
    fn a_value_of_another_type_is_an_asn1_error_and_cut_input_an_io_error() {
        let crl = data("crl");
        let mut parser = DerParserEntry::certificates().create();
        assert!(matches!(
            parser.parse(&mut &crl[..]),
            Err(X509Error::Asn1(_))
        ));

        let mut parser = DerParserEntry::certificates().create();
        assert!(matches!(
            parser.parse(&mut &[0x30, 0x05, 0x02][..]),
            Err(X509Error::Io(_))
        ));
    }
}
