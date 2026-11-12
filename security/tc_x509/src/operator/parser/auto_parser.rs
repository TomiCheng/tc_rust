use std::io::Read;
use std::vec;

use tc_asn1::io::Asn1Reader;
use tc_asn1::{Asn1Any, Asn1Error, Decode, DecodingOptions};
use tc_asn1_cms::content::ContentInfo;
use tc_pem::PemReader;

use super::der_parser::from_io;
use super::pem_parser::{self, OneOctet, PemParserEntry};
use super::pkcs7_parser::{self, Pkcs7ParserEntry};
use super::{Parser, ParserEntry};
use crate::X509Error;
use crate::cert::{X509AttributeCertificate, X509Certificate};
use crate::crl::X509Crl;

// The tag of an OBJECT IDENTIFIER, the first field of a ContentInfo and of no certificate
const OID: u8 = 0x06;

// The "AUTO" format: each value in whichever of DER, PEM and PKCS #7 it comes, told from its
// first octet, as BC's parsers tell it. Text is PEM, where a block labelled PKCS7 is a bundle;
// a SEQUENCE whose first field is an OBJECT IDENTIFIER is a PKCS #7 ContentInfo, any other one
// a value of the type. The octet read to tell is chained back before the value is read, so
// nothing past the value is read
pub(crate) struct AutoParser<T> {
    labels: &'static [&'static str],
    decode: pem_parser::Decode<T>,
    extract: pkcs7_parser::Extract<T>,
    pending: vec::IntoIter<T>,
}

impl<T> AutoParser<T> {
    fn values_of_pkcs7(&self, encoding: &[u8]) -> Result<Vec<T>, X509Error> {
        let (_, info) = ContentInfo::decode(encoding, &DecodingOptions::default())?;
        pkcs7_parser::values_of(&info, self.extract)
    }

    // The next value from PEM blocks: one of the type, or the first of a PKCS7 bundle
    fn parse_pem(&mut self, input: &mut dyn Read) -> Result<Option<T>, X509Error> {
        let mut reader = PemReader::new(OneOctet::new(input));
        while let Some(object) = reader.read_pem_object()? {
            if self.labels.contains(&object.pem_type()) {
                return Ok(Some((self.decode)(object.content())?));
            }
            if object.pem_type() == "PKCS7" {
                self.pending = self.values_of_pkcs7(object.content())?.into_iter();
                if let Some(value) = self.pending.next() {
                    return Ok(Some(value));
                }
            }
        }
        Ok(None)
    }

    // The value of a DER SEQUENCE, or the first of a PKCS #7 bundle; None when a bundle holds
    // none of the type, for the caller to read on
    fn parse_der(&mut self, input: &mut dyn Read) -> Result<Option<T>, X509Error> {
        let mut reader = Asn1Reader::new(input, DecodingOptions::default());
        let Some(value) = reader.read_value::<Asn1Any>().map_err(from_io)? else {
            return Ok(None);
        };
        if value.as_ref().value().first() == Some(&OID) {
            self.pending = self.values_of_pkcs7(value.raw())?.into_iter();
            return Ok(self.pending.next());
        }
        Ok(Some((self.decode)(value.raw())?))
    }
}

impl<T> Parser<T> for AutoParser<T> {
    fn parse(&mut self, input: &mut dyn Read) -> Result<Option<T>, X509Error> {
        loop {
            if let Some(value) = self.pending.next() {
                return Ok(Some(value));
            }
            let mut first = [0u8; 1];
            loop {
                match input.read(&mut first) {
                    Ok(0) => return Ok(None),
                    Ok(_) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            let mut joined = (&first[..]).chain(&mut *input);
            match first[0] {
                b'-' | b' ' | b'\t' | b'\r' | b'\n' => return self.parse_pem(&mut joined),
                0x30 => {
                    if let Some(value) = self.parse_der(&mut joined)? {
                        return Ok(Some(value));
                    }
                }
                _ => return Err(X509Error::Asn1(Asn1Error::UnexpectedTag)),
            }
        }
    }
}

pub(crate) struct AutoParserEntry<T> {
    pem: PemParserEntry<T>,
    pkcs7: Pkcs7ParserEntry<T>,
}

impl AutoParserEntry<X509Certificate> {
    pub(crate) fn certificates() -> Self {
        Self {
            pem: PemParserEntry::certificates(),
            pkcs7: Pkcs7ParserEntry::certificates(),
        }
    }
}

impl AutoParserEntry<X509Crl> {
    pub(crate) fn crls() -> Self {
        Self {
            pem: PemParserEntry::crls(),
            pkcs7: Pkcs7ParserEntry::crls(),
        }
    }
}

impl AutoParserEntry<X509AttributeCertificate> {
    pub(crate) fn attribute_certificates() -> Self {
        Self {
            pem: PemParserEntry::attribute_certificates(),
            pkcs7: Pkcs7ParserEntry::attribute_certificates(),
        }
    }
}

impl<T: 'static> ParserEntry<T> for AutoParserEntry<T> {
    fn name(&self) -> &str {
        "AUTO"
    }

    fn create(&self) -> Box<dyn Parser<T>> {
        Box::new(AutoParser {
            labels: self.pem.labels,
            decode: self.pem.decode,
            extract: self.pkcs7.extract,
            pending: Vec::new().into_iter(),
        })
    }
}
