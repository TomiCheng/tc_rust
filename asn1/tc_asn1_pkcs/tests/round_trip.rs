use std::fmt::Debug;

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Integer, Asn1OctetString, Decode, DecodingOptions, Encode,
    EncodingOptions, tag,
};
use tc_asn1_cms::content::ContentType;
use tc_asn1_pkcs::{
    Attribute, CertBag, CertificationRequestInfo, ContentInfo, CrlBag, DhParameter, DigestInfo,
    MacData, Pbmac1Params, Pfx, Pkcs5Algorithm, Pkcs9Attribute, Pkcs12Algorithm, Pkcs12PbeParams,
    SafeBag, ScryptParams, SignedData,
};
use tc_asn1_x500::{AttributeValue, Name};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

fn round_trip<T: Decode + Encode + PartialEq + Debug>(value: &T) -> Vec<u8> {
    let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
    let (len, back) = T::decode_der(&der, &DecodingOptions::default()).unwrap();
    assert_eq!(len, der.len());
    assert_eq!(&back, value);
    der
}

fn octet_string(bytes: &[u8]) -> Asn1Any {
    Asn1Any::primitive(tag::OCTET_STRING, bytes)
}

fn local_key_id() -> Attribute {
    Attribute::new(
        Pkcs9Attribute::LOCAL_KEY_ID.oid(),
        vec![AttributeValue::Other(
            Asn1OctetString::new(&[1, 2, 3]).into(),
        )],
    )
    .unwrap()
}

#[test]
fn dh_parameters_round_trip_with_and_without_a_private_value_length() {
    let params = DhParameter::new(23.into(), 5.into());
    assert_eq!(round_trip(&params), [0x30, 6, 2, 1, 23, 2, 1, 5]);
    round_trip(&params.with_l(160.into()));
}

#[test]
fn scrypt_parameters_round_trip_with_an_optional_key_length() {
    let params = ScryptParams::new(
        Asn1OctetString::new(b"NaCl"),
        1024.into(),
        8.into(),
        16.into(),
    );
    round_trip(&params);
    let params = params.with_key_length(64.into());
    assert_eq!(params.key_length(), Some(&64.into()));
    round_trip(&params);
}

#[test]
fn pbmac1_and_pkcs12_pbe_parameters_round_trip() {
    round_trip(&Pbmac1Params::new(
        AlgorithmIdentifier::new(Pkcs5Algorithm::PBKDF2.oid()),
        AlgorithmIdentifier::with_null(Pkcs5Algorithm::HMAC_WITH_SHA256.oid()),
    ));
    round_trip(&Pkcs12PbeParams::new(
        Asn1OctetString::new(&[7; 20]),
        2048.into(),
    ));
}

#[test]
fn certificate_and_crl_bags_wrap_their_values_in_explicit_tags() {
    let bag = CertBag::new(
        Pkcs9Attribute::X509_CERTIFICATE.oid(),
        octet_string(&[0x30, 0]),
    );
    let der = round_trip(&bag);
    assert_eq!(&der[der.len() - 6..], [0xa0, 4, 4, 2, 0x30, 0]);
    round_trip(&CrlBag::new(
        Pkcs9Attribute::X509_CRL.oid(),
        octet_string(&[0x30, 0]),
    ));
}

#[test]
fn safe_bags_keep_their_attributes() {
    let bag = SafeBag::new(Pkcs12Algorithm::CERT_BAG.oid(), octet_string(&[0x30, 0]));
    assert!(round_trip(&bag).ends_with(&[0xa0, 4, 4, 2, 0x30, 0]));
    let bag = bag.with_bag_attributes(vec![local_key_id()]);
    round_trip(&bag);
    assert_eq!(bag.bag_attributes(), Some(&[local_key_id()][..]));
}

#[test]
fn certification_request_info_writes_an_empty_attribute_set_only_when_asked() {
    let spki = SubjectPublicKeyInfo::decode_der(
        &[0x30, 10, 0x30, 5, 6, 3, 0x2b, 0x65, 0x6e, 3, 1, 0],
        &DecodingOptions::default(),
    )
    .unwrap()
    .1;
    let info = CertificationRequestInfo::new(Name::new(vec![]), spki);
    assert!(!round_trip(&info).ends_with(&[0xa0, 0]));
    let info = info.with_attributes(vec![]);
    assert!(round_trip(&info).ends_with(&[0xa0, 0]));
    assert_eq!(info.version(), 0.into());
}

#[test]
fn certificates_only_signed_data_is_version_1() {
    let data = SignedData::new(vec![], ContentInfo::new(ContentType::DATA.oid()), vec![]);
    assert_eq!(data.version(), 1.into());
    round_trip(&data);
}

#[test]
fn pfx_versions_other_than_3_are_rejected() {
    let info = ContentInfo::new(ContentType::DATA.oid()).with_content(octet_string(&[0x30, 0]));
    let mut der = round_trip(&Pfx::new(info));
    assert_eq!(der[2..5], [2, 1, 3]);
    der[4] = 2;
    assert_eq!(
        Pfx::decode(&der, &DecodingOptions::default()).unwrap_err(),
        Asn1Error::MalformedValue
    );
}

#[test]
fn mac_data_omits_the_default_iteration_count_and_rejects_it_written_under_der() {
    let mac = DigestInfo::new(
        AlgorithmIdentifier::with_null("1.3.14.3.2.26".parse().unwrap()),
        &[0; 20],
    );
    let data = MacData::new(mac.clone(), Asn1OctetString::new(&[9; 8]));
    let without = round_trip(&data);
    round_trip(&data.clone().with_iterations(2048.into()));

    let mut content = without[2..].to_vec();
    content.extend(
        Asn1Integer::from(1)
            .encode_to_vec(&EncodingOptions::DER)
            .unwrap(),
    );
    let mut written = vec![0x30, content.len() as u8];
    written.extend(content);
    let options = DecodingOptions::default();
    assert_eq!(MacData::decode(&written, &options).unwrap().1, data);
    assert!(MacData::decode_der(&written, &options).is_err());
}

#[test]
fn oid_tables_find_their_entries() {
    let entries = [
        Pkcs9Attribute::FRIENDLY_NAME,
        Pkcs12Algorithm::PKCS8_SHROUDED_KEY_BAG,
        Pkcs5Algorithm::SCRYPT,
    ];
    assert_eq!(
        Pkcs9Attribute::from_oid(&entries[0].oid()),
        Some(entries[0])
    );
    assert_eq!(
        Pkcs12Algorithm::from_oid(&entries[1].oid()),
        Some(entries[1])
    );
    assert_eq!(
        Pkcs5Algorithm::from_oid(&entries[2].oid()),
        Some(entries[2])
    );
    assert_eq!(Pkcs5Algorithm::SCRYPT.dotted(), "1.3.6.1.4.1.11591.4.11");
}
