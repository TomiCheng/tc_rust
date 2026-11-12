use std::io::Read;
use std::vec;

use tc_asn1::io::Asn1Reader;
use tc_asn1::{Asn1Error, Decode, DecodingOptions};
use tc_asn1_cms::content::{CertificateChoices, ContentInfo, ContentType, RevocationInfoChoice};
use tc_asn1_pkcs::SignedData;

use super::der_parser::from_io;
use super::{Parser, ParserEntry};
use crate::X509Error;
use crate::cert::{X509AttributeCertificate, X509Certificate};
use crate::crl::X509Crl;

// Takes the values of its type out of a SignedData
pub(super) type Extract<T> = fn(&SignedData) -> Result<Vec<T>, X509Error>;

// The values of its type a ContentInfo of SignedData carries
pub(super) fn values_of<T>(info: &ContentInfo, extract: Extract<T>) -> Result<Vec<T>, X509Error> {
    if ContentType::SIGNED_DATA != *info.content_type() {
        return Err(X509Error::Asn1(Asn1Error::UnexpectedTag));
    }
    let content = info
        .content()
        .ok_or(X509Error::Asn1(Asn1Error::MalformedValue))?;
    let (_, signed_data) = SignedData::decode(content.raw(), &DecodingOptions::default())?;
    extract(&signed_data)
}

// The "PKCS7" format: PKCS #7 SignedData, one after another, as a .p7b carries certificates
// and CRLs. The values of each are given one per call, those of its type only; the signers are
// not verified, since a bundle has none
pub(crate) struct Pkcs7Parser<T> {
    extract: Extract<T>,
    pending: vec::IntoIter<T>,
}

impl<T> Parser<T> for Pkcs7Parser<T> {
    fn parse(&mut self, input: &mut dyn Read) -> Result<Option<T>, X509Error> {
        loop {
            if let Some(value) = self.pending.next() {
                return Ok(Some(value));
            }
            let mut reader = Asn1Reader::new(&mut *input, DecodingOptions::default());
            let Some(info) = reader.read_value::<ContentInfo>().map_err(from_io)? else {
                return Ok(None);
            };
            self.pending = values_of(&info, self.extract)?.into_iter();
        }
    }
}

pub(crate) struct Pkcs7ParserEntry<T> {
    pub(super) extract: Extract<T>,
}

impl Pkcs7ParserEntry<X509Certificate> {
    pub(crate) fn certificates() -> Self {
        Self {
            extract: |signed_data| {
                Ok(signed_data
                    .certificates()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|choice| match choice {
                        CertificateChoices::Certificate(certificate) => {
                            Some(X509Certificate::new(certificate.clone()))
                        }
                        _ => None,
                    })
                    .collect())
            },
        }
    }
}

impl Pkcs7ParserEntry<X509Crl> {
    pub(crate) fn crls() -> Self {
        Self {
            extract: |signed_data| {
                signed_data
                    .crls()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|choice| match choice {
                        RevocationInfoChoice::Crl(list) => Some(X509Crl::new(list.clone())),
                        _ => None,
                    })
                    .collect::<Result<_, _>>()
                    .map_err(X509Error::Asn1)
            },
        }
    }
}

impl Pkcs7ParserEntry<X509AttributeCertificate> {
    pub(crate) fn attribute_certificates() -> Self {
        Self {
            extract: |signed_data| {
                Ok(signed_data
                    .certificates()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|choice| match choice {
                        CertificateChoices::V2AttrCert(certificate) => {
                            Some(X509AttributeCertificate::new(certificate.clone()))
                        }
                        _ => None,
                    })
                    .collect())
            },
        }
    }
}

impl<T: 'static> ParserEntry<T> for Pkcs7ParserEntry<T> {
    fn name(&self) -> &str {
        "PKCS7"
    }

    fn create(&self) -> Box<dyn Parser<T>> {
        Box::new(Pkcs7Parser {
            extract: self.extract,
            pending: Vec::new().into_iter(),
        })
    }
}
