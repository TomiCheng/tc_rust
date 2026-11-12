//! Parsers that read certificates, CRLs and attribute certificates from a `std::io::Read`, each
//! for one format, found by name through an `X509Operator`: BC's `X509CertificateParser` and
//! `X509CrlParser`, split by format and open to formats of one's own.

mod default_parser_provider;
mod der_parser;
mod pem_parser;
mod pkcs7_parser;
mod traits;

use crate::DefaultX509OperatorContext;
use crate::cert::{X509AttributeCertificate, X509Certificate};
use crate::crl::X509Crl;

pub(crate) use default_parser_provider::DefaultParserProvider;
pub use traits::{Parser, ParserEntry, ParserProvider};

// What a builder calls to make the parser rows of T
pub(crate) type CreateRows<T> = fn(&DefaultX509OperatorContext) -> Vec<Box<dyn ParserEntry<T>>>;

// What DefaultX509OperatorBuilder starts with
pub(crate) const CERTIFICATE_BUILT_IN: &[CreateRows<X509Certificate>] = &[certificate_rows];
pub(crate) const CRL_BUILT_IN: &[CreateRows<X509Crl>] = &[crl_rows];
pub(crate) const ATTRIBUTE_CERTIFICATE_BUILT_IN: &[CreateRows<X509AttributeCertificate>] =
    &[attribute_certificate_rows];

fn certificate_rows(_: &DefaultX509OperatorContext) -> Vec<Box<dyn ParserEntry<X509Certificate>>> {
    vec![
        Box::new(der_parser::DerParserEntry::certificates()),
        Box::new(pem_parser::PemParserEntry::certificates()),
        Box::new(pkcs7_parser::Pkcs7ParserEntry::certificates()),
    ]
}

fn crl_rows(_: &DefaultX509OperatorContext) -> Vec<Box<dyn ParserEntry<X509Crl>>> {
    vec![
        Box::new(der_parser::DerParserEntry::crls()),
        Box::new(pem_parser::PemParserEntry::crls()),
        Box::new(pkcs7_parser::Pkcs7ParserEntry::crls()),
    ]
}

fn attribute_certificate_rows(
    _: &DefaultX509OperatorContext,
) -> Vec<Box<dyn ParserEntry<X509AttributeCertificate>>> {
    vec![
        Box::new(der_parser::DerParserEntry::attribute_certificates()),
        Box::new(pem_parser::PemParserEntry::attribute_certificates()),
        Box::new(pkcs7_parser::Pkcs7ParserEntry::attribute_certificates()),
    ]
}
