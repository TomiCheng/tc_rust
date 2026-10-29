use std::fmt::Debug;

use tc_asn1::{
    Asn1Boolean, Asn1Error, Asn1GeneralizedTime, Asn1Ia5String, Asn1OctetString,
    Asn1PrintableString, Decode, DecodingOptions, Encode, EncodingOptions,
};
use tc_asn1_isismtt::{
    AdmissionSyntax, Admissions, CertHash, DeclarationOfMajority, FullAgeAtCountry, IsisMttId,
    MonetaryLimit, NamingAuthority, ProcurationSyntax, ProfessionInfo, RequestedCertificate,
    SigningFor,
};
use tc_asn1_x500::DirectoryString;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::attr::IssuerSerial;
use tc_asn1_x509::cert::Certificate;
use tc_asn1_x509::name::{GeneralName, GeneralNames};

const BC_SSLEAY_CERTIFICATE: &[u8] = include_bytes!("data/bc_ssleay_certificate.der");
const RFC_8410: &[u8] = include_bytes!("data/rfc8410.der");

fn round_trip<T: Decode + Encode + PartialEq + Debug>(value: &T) -> Vec<u8> {
    let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
    assert_eq!(
        T::decode_der(&der, &DecodingOptions::default()).unwrap().1,
        *value
    );
    der
}

fn printable(s: &str) -> Asn1PrintableString {
    Asn1PrintableString::new(s).unwrap()
}

fn text(s: &str) -> DirectoryString {
    DirectoryString::new(s).unwrap()
}

fn naming_authority() -> NamingAuthority {
    NamingAuthority::new()
        .with_naming_authority_id("1.2.3".parse().unwrap())
        .with_naming_authority_url(Asn1Ia5String::new("https://example.com").unwrap())
        .with_naming_authority_text(text("Chamber"))
}

#[test]
fn requested_certificate_holds_a_certificate_or_its_encoding() {
    let certificate = Certificate::decode(RFC_8410, &DecodingOptions::default())
        .unwrap()
        .1;
    let requested = RequestedCertificate::Certificate(certificate);
    // The TBS is kept as found, so the BER certificate stays BER.
    let encoding = requested.encode_to_vec(&EncodingOptions::DER).unwrap();
    assert_eq!(encoding, RFC_8410);
    assert_eq!(
        RequestedCertificate::decode(&encoding, &DecodingOptions::default())
            .unwrap()
            .1,
        requested
    );

    let octets = Asn1OctetString::new(&[0; 20]);
    let attribute = RequestedCertificate::AttributeCertificate(octets.clone());
    assert_eq!(round_trip(&attribute)[..4], [0xa1, 22, 0x04, 20]);
    let public_key = RequestedCertificate::PublicKeyCertificate(octets);
    assert_eq!(round_trip(&public_key)[0], 0xa0);
}

/// BC's certificate signs with md5WithRSAEncryption but names md5 outside,
/// which RFC 5280 §4.1.1.2 forbids.
#[test]
fn bc_certificate_with_mismatched_signature_algorithms_is_rejected() {
    assert_eq!(
        RequestedCertificate::decode(BC_SSLEAY_CERTIFICATE, &DecodingOptions::default()),
        Err(Asn1Error::MalformedValue)
    );
}

#[test]
fn bc_declaration_of_majority_omits_a_true_full_age() {
    let full_age = FullAgeAtCountry::new(printable("AU"));
    let declaration = DeclarationOfMajority::FullAgeAtCountry(full_age.clone());
    assert_eq!(round_trip(&declaration), [0xa1, 4, 0x13, 2, b'A', b'U']);
    let not_full_age =
        FullAgeAtCountry::new(printable("AU")).with_full_age(Asn1Boolean::from(false));
    assert_eq!(
        round_trip(&DeclarationOfMajority::FullAgeAtCountry(not_full_age)),
        [0xa1, 7, 1, 1, 0, 0x13, 2, b'A', b'U']
    );
    assert_eq!(
        DeclarationOfMajority::decode_der(
            &[0xa1, 7, 1, 1, 0xff, 0x13, 2, b'A', b'U'],
            &DecodingOptions::default()
        ),
        Err(Asn1Error::NotDer)
    );

    assert_eq!(
        round_trip(&DeclarationOfMajority::NotYoungerThan(18.into())),
        [0x80, 1, 18]
    );
    let birth =
        Asn1GeneralizedTime::decode_der(b"\x18\x0f19700101000000Z", &DecodingOptions::default())
            .unwrap()
            .1;
    assert_eq!(
        round_trip(&DeclarationOfMajority::DateOfBirth(birth))[0],
        0x82
    );
}

#[test]
fn bc_admissions_round_trip_with_and_without_a_default_authority() {
    let profession = ProfessionInfo::new(vec![text("Lawyer")])
        .with_naming_authority(naming_authority())
        .with_profession_oids(vec!["1.2.3.4".parse().unwrap()])
        .with_registration_number(printable("12345"))
        .with_add_profession_info(Asn1OctetString::new(&[1, 2]));
    round_trip(&profession);
    let admissions = Admissions::new(vec![profession])
        .with_admission_authority(GeneralName::DirectoryName("CN=Bar".parse().unwrap()))
        .with_naming_authority(naming_authority());
    round_trip(&admissions);

    let without = AdmissionSyntax::new(vec![admissions.clone()]);
    round_trip(&without);
    let with = without
        .with_admission_authority(GeneralName::DirectoryName("CN=Authority".parse().unwrap()));
    let der = round_trip(&with);
    let decoded = AdmissionSyntax::decode_der(&der, &DecodingOptions::default())
        .unwrap()
        .1;
    assert!(decoded.admission_authority().is_some());
}

#[test]
fn bc_procuration_signs_for_a_person_or_a_certificate() {
    let person = ProcurationSyntax::new(SigningFor::ThirdPerson(GeneralName::DirectoryName(
        "CN=Principal".parse().unwrap(),
    )))
    .with_country(printable("AU"))
    .with_type_of_substitution(text("substitution"));
    round_trip(&person);

    let issuer =
        GeneralNames::new(vec![GeneralName::DirectoryName("CN=CA".parse().unwrap())]).unwrap();
    let certificate =
        ProcurationSyntax::new(SigningFor::CertRef(IssuerSerial::new(issuer, 7.into())));
    let der = round_trip(&certificate);
    assert_eq!(der[2..4], [0xa3, der[3]]);
    assert_eq!(der[4], 0x30);
}

#[test]
fn bc_monetary_limit_naming_authority_and_cert_hash_round_trip() {
    round_trip(&MonetaryLimit::new(printable("AUD"), 1.into(), 2.into()));
    round_trip(&naming_authority());
    assert_eq!(round_trip(&NamingAuthority::new()), [0x30, 0]);
    round_trip(&CertHash::new(
        AlgorithmIdentifier::new("1.3.14.3.2.26".parse().unwrap()),
        Asn1OctetString::new(&[0; 20]),
    ));
}

#[test]
fn isis_mtt_attributes_sit_under_their_arc() {
    assert_eq!(IsisMttId::ADMISSION.dotted(), "1.3.36.8.3.3");
    assert_eq!(
        IsisMttId::from_oid(&IsisMttId::CERT_HASH.oid()),
        Some(IsisMttId::CERT_HASH)
    );
}
