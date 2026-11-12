use std::sync::Arc;

use tc_algo::Params;
use tc_asn1::{Asn1BitString, Asn1Integer};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::{Time, Version};
use tc_asn1_x509::crl::{
    CertificateList, IssuingDistributionPoint, RevokedCertificate, TbsCertList,
};
use tc_asn1_x509::ext::{Extension, ExtensionId, Extensions};
use tc_asn1_x509::name::{GeneralName, GeneralNames};
use tc_x509::cert::{X509Certificate, X509V3CertificateGenerator};
use tc_x509::crl::X509Crl;
use tc_x509::operator::params::RsaKeyGenParams;
use tc_x509::{DefaultX509OperatorBuilder, X509Error, X509Operator, X509OperatorBuilder};

const CA: &[u8] = include_bytes!("data/crl/ca.der");
const REVOKED: &[u8] = include_bytes!("data/crl/revoked.der");
const GOOD: &[u8] = include_bytes!("data/crl/good.der");
const CRL: &[u8] = include_bytes!("data/crl/crl.der");

#[test]
fn the_openssl_crl_exposes_its_fields_and_round_trips() {
    let crl = X509Crl::decode(CRL).unwrap();
    let ca = X509Certificate::decode(CA).unwrap();

    assert_eq!(crl.version(), Version::V2);
    assert!(crl.issuer().equivalent(ca.subject()));
    assert!(crl.next_update().unwrap() > crl.this_update());
    assert!(!crl.is_indirect());
    assert!(crl.extensions().is_some());
    assert_eq!(crl.encode().unwrap(), CRL);

    let entries = crl.revoked_certificates();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].certificate_issuer().is_none());
    assert!(entries[0].extensions().is_some());
}

#[test]
fn the_openssl_crl_verifies_with_the_ca_key_and_not_with_another() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let crl = X509Crl::decode(CRL).unwrap();
    let ca = X509Certificate::decode(CA).unwrap();
    let key = oper.spki().decode(ca.subject_public_key_info()).unwrap();
    crl.verify(oper.verifier_factory_provider(key.into()).as_ref())
        .unwrap();

    let good = X509Certificate::decode(GOOD).unwrap();
    let other = oper.spki().decode(good.subject_public_key_info()).unwrap();
    let error = crl
        .verify(oper.verifier_factory_provider(other.into()).as_ref())
        .err()
        .unwrap();
    assert!(matches!(error, X509Error::InvalidSignature));
}

#[test]
fn only_the_listed_certificate_of_the_crl_issuer_is_revoked() {
    let crl = X509Crl::decode(CRL).unwrap();
    let revoked = X509Certificate::decode(REVOKED).unwrap();
    let good = X509Certificate::decode(GOOD).unwrap();

    assert!(crl.is_revoked(&revoked));
    assert!(!crl.is_revoked(&good));
    let entry = crl.revoked_certificate(revoked.serial_number()).unwrap();
    assert_eq!(entry.serial_number(), revoked.serial_number());
    assert!(crl.revoked_certificate(good.serial_number()).is_none());
}

fn keys(oper: &dyn X509Operator) -> (Arc<dyn Params>, Arc<dyn Params>) {
    let mut key_gen = oper.key_pair_generator().get_by_name("RSA").unwrap();
    // Small, since generating the primes is slow
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    let (public, private) = key_gen.generate().unwrap().into_parts();
    (public.into(), private.into())
}

fn certificate(
    oper: &dyn X509Operator,
    keys: &(Arc<dyn Params>, Arc<dyn Params>),
    issuer: &str,
    serial: i64,
) -> X509Certificate {
    let mut generator = X509V3CertificateGenerator::new();
    generator
        .set_serial_number(Asn1Integer::from(serial))
        .unwrap();
    generator.set_issuer_by_str(issuer).unwrap();
    generator.set_subject_by_str("CN=Leaf").unwrap();
    generator.set_validity_days(30).unwrap();
    generator.set_subject_public_key_info(oper.spki().encode(keys.0.as_ref()).unwrap());
    let signer = oper
        .signature_factory("SHA-256withRSA", keys.1.clone())
        .unwrap();
    generator.generate(signer.as_ref()).unwrap()
}

fn entry(serial: i64, now: Time) -> RevokedCertificate {
    RevokedCertificate::new(Asn1Integer::from(serial), now)
}

// An indirect CRL of "CN=CRL Issuer": serial 1 of its own, then serials 2 and 3 of "CN=Other CA",
// named by the certificateIssuer extension of the first of them only. Not signed; only the
// lookup is tested
fn indirect_crl() -> X509Crl {
    let now = Time::try_from(chrono::Utc::now()).unwrap();
    let other = GeneralNames::new(vec![GeneralName::DirectoryName(
        "CN=Other CA".parse().unwrap(),
    )])
    .unwrap();
    let certificate_issuer =
        Extension::with_value(ExtensionId::CERTIFICATE_ISSUER, true, &other).unwrap();
    let entries = vec![
        entry(1, now),
        entry(2, now).with_extensions(Extensions::new(vec![certificate_issuer]).unwrap()),
        entry(3, now),
    ];
    let point = IssuingDistributionPoint::new(None, false, false, None, true, false).unwrap();
    let extensions = Extensions::new(vec![
        Extension::with_value(ExtensionId::ISSUING_DISTRIBUTION_POINT, true, &point).unwrap(),
    ])
    .unwrap();
    let algorithm = AlgorithmIdentifier::new("1.2.840.113549.1.1.11".parse().unwrap());
    let tbs = TbsCertList::new(
        Version::V2,
        algorithm,
        "CN=CRL Issuer".parse().unwrap(),
        now,
    )
    .unwrap()
    .with_revoked_certificates(entries)
    .unwrap()
    .with_extensions(extensions)
    .unwrap();
    let list = CertificateList::new(tbs, Asn1BitString::from_bytes(&[0])).unwrap();
    X509Crl::new(list).unwrap()
}

#[test]
fn an_indirect_crl_carries_the_certificate_issuer_to_the_entries_after_it() {
    let crl = indirect_crl();
    assert!(crl.is_indirect());

    let issuers: Vec<Option<String>> = crl
        .revoked_certificates()
        .iter()
        .map(|entry| entry.certificate_issuer().map(ToString::to_string))
        .collect();
    let other = Some("CN=Other CA".to_string());
    assert_eq!(issuers, [None, other.clone(), other]);
}

#[test]
fn an_indirect_crl_matches_a_certificate_by_its_issuer_as_well_as_its_serial_number() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let keys = keys(oper.as_ref());
    let crl = indirect_crl();

    assert!(crl.is_revoked(&certificate(oper.as_ref(), &keys, "CN=CRL Issuer", 1)));
    assert!(crl.is_revoked(&certificate(oper.as_ref(), &keys, "CN=Other CA", 3)));
    assert!(!crl.is_revoked(&certificate(oper.as_ref(), &keys, "CN=Other CA", 1)));
    assert!(!crl.is_revoked(&certificate(oper.as_ref(), &keys, "CN=CRL Issuer", 3)));
    assert!(!crl.is_revoked(&certificate(oper.as_ref(), &keys, "CN=Third CA", 2)));
}
