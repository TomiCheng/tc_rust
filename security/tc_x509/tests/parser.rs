use std::io::Read;

use tc_x509::cert::X509Certificate;
use tc_x509::operator::parser::{Parser, ParserEntry};
use tc_x509::{
    DefaultX509OperatorBuilder, DefaultX509OperatorContext, X509Error, X509Operator,
    X509OperatorBuilder,
};

const CA: &[u8] = include_bytes!("data/crl/ca.der");
const GOOD: &[u8] = include_bytes!("data/crl/good.der");
const CRL: &[u8] = include_bytes!("data/crl/crl.der");
const BUNDLE: &[u8] = include_bytes!("data/crl/bundle.p7b");
const CHAIN: &[u8] = include_bytes!("data/crl/chain.pem");

#[test]
fn the_operator_gives_a_der_parser_by_name_in_any_case() {
    let operator = DefaultX509OperatorBuilder::default().build();
    assert_eq!(
        operator.certificate_parser().names(),
        ["DER", "PEM", "PKCS7"]
    );

    let input = [CA, GOOD].concat();
    let mut source = &input[..];
    let mut parser = operator.certificate_parser().get_by_name("der").unwrap();
    let mut count = 0;
    while parser.parse(&mut source).unwrap().is_some() {
        count += 1;
    }
    assert_eq!(count, 2);

    let mut parser = operator.crl_parser().get_by_name("DER").unwrap();
    assert!(parser.parse(&mut &CRL[..]).unwrap().is_some());
}

#[test]
fn a_name_no_parser_has_is_unknown_parser() {
    let operator = DefaultX509OperatorBuilder::default().build();
    assert!(matches!(
        operator.certificate_parser().get_by_name("NOPE"),
        Err(X509Error::UnknownParser)
    ));
}

// A format of one's own: every value is the CA certificate, once
struct Fixed;

struct FixedParser {
    given: bool,
}

impl Parser<X509Certificate> for FixedParser {
    fn parse(&mut self, _: &mut dyn Read) -> Result<Option<X509Certificate>, X509Error> {
        if self.given {
            return Ok(None);
        }
        self.given = true;
        Ok(Some(X509Certificate::decode(CA)?))
    }
}

impl ParserEntry<X509Certificate> for Fixed {
    fn name(&self) -> &str {
        "FIXED"
    }

    fn create(&self) -> Box<dyn Parser<X509Certificate>> {
        Box::new(FixedParser { given: false })
    }
}

fn fixed_rows(_: &DefaultX509OperatorContext) -> Vec<Box<dyn ParserEntry<X509Certificate>>> {
    vec![Box::new(Fixed)]
}

#[test]
fn a_registered_parser_is_found_by_its_name_beside_the_built_in_ones() {
    let mut builder = DefaultX509OperatorBuilder::default();
    builder.reg_certificate_parser(fixed_rows);
    let operator = builder.build();
    assert_eq!(
        operator.certificate_parser().names(),
        ["FIXED", "DER", "PEM", "PKCS7"]
    );

    let mut parser = operator.certificate_parser().get_by_name("fixed").unwrap();
    assert!(parser.parse(&mut &[][..]).unwrap().is_some());
    assert!(parser.parse(&mut &[][..]).unwrap().is_none());
}

#[test]
fn the_pkcs7_parser_gives_the_certificates_of_a_bundle_one_at_a_time() {
    let operator = DefaultX509OperatorBuilder::default().build();
    let mut parser = operator.certificate_parser().get_by_name("PKCS7").unwrap();
    let mut source = BUNDLE;
    let mut subjects = Vec::new();
    while let Some(certificate) = parser.parse(&mut source).unwrap() {
        subjects.push(certificate.subject().to_string());
    }
    assert_eq!(subjects, ["CN=Test CA", "CN=good", "CN=revoked"]);
    assert!(source.is_empty());
}

#[test]
fn the_same_bundle_gives_its_crls_to_a_crl_parser() {
    let operator = DefaultX509OperatorBuilder::default().build();
    let mut parser = operator.crl_parser().get_by_name("pkcs7").unwrap();
    let mut source = BUNDLE;
    let crl = parser.parse(&mut source).unwrap().unwrap();
    assert_eq!(crl.encode().unwrap(), CRL);
    assert!(parser.parse(&mut source).unwrap().is_none());

    let mut parser = operator
        .attribute_certificate_parser()
        .get_by_name("PKCS7")
        .unwrap();
    assert!(parser.parse(&mut &BUNDLE[..]).unwrap().is_none());
}

#[test]
fn a_der_certificate_given_to_the_pkcs7_parser_is_an_asn1_error() {
    let operator = DefaultX509OperatorBuilder::default().build();
    let mut parser = operator.certificate_parser().get_by_name("PKCS7").unwrap();
    assert!(matches!(
        parser.parse(&mut &CA[..]),
        Err(X509Error::Asn1(_))
    ));
}

#[test]
fn the_pem_parser_takes_the_blocks_of_its_type_and_passes_over_the_others() {
    let operator = DefaultX509OperatorBuilder::default().build();
    let mut parser = operator.certificate_parser().get_by_name("PEM").unwrap();
    let mut source = CHAIN;
    let mut subjects = Vec::new();
    while let Some(certificate) = parser.parse(&mut source).unwrap() {
        subjects.push(certificate.subject().to_string());
    }
    assert_eq!(subjects, ["CN=Test CA", "CN=good", "CN=revoked"]);

    let mut parser = operator.crl_parser().get_by_name("PEM").unwrap();
    let mut source = CHAIN;
    let crl = parser.parse(&mut source).unwrap().unwrap();
    assert_eq!(crl.encode().unwrap(), CRL);
    assert!(parser.parse(&mut source).unwrap().is_none());
}

#[test]
fn the_pem_parser_reads_nothing_past_the_block_it_gives() {
    let operator = DefaultX509OperatorBuilder::default().build();
    let mut parser = operator.certificate_parser().get_by_name("PEM").unwrap();
    let mut source = CHAIN;
    parser.parse(&mut source).unwrap().unwrap();
    let rest = std::str::from_utf8(source).unwrap();
    assert!(rest.trim_start().starts_with("-----BEGIN X509 CRL-----"));
}

#[test]
fn a_block_that_is_not_base64_is_an_error() {
    let operator = DefaultX509OperatorBuilder::default().build();
    let mut parser = operator.certificate_parser().get_by_name("PEM").unwrap();
    let broken = b"-----BEGIN CERTIFICATE-----
!!!!
-----END CERTIFICATE-----
";
    assert!(parser.parse(&mut &broken[..]).is_err());
}
