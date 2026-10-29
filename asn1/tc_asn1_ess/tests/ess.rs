use std::fmt::Debug;

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1GeneralizedTime, Asn1Object, Asn1OctetString, Asn1Utf8String, Decode,
    DecodingOptions, Encode, EncodingOptions, tag,
};
use tc_asn1_cms::recipient::RecipientKeyIdentifier;
use tc_asn1_ess::{
    ContentHints, EssAttribute, EssCertId, EssCertIdV2, SigningCertificate, SigningCertificateV2,
    SmimeAttribute, SmimeCapabilities, SmimeCapability, SmimeCapabilityId,
    SmimeEncryptionKeyPreference,
};
use tc_asn1_x500::{Attribute, AttributeValue};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::ext::SubjectKeyIdentifier;

/// BC `SmimeTest.attrBytes`: 3DES, RC2-128 and DES.
const CAPABILITIES_ATTRIBUTE: &[u8] = &[
    0x30, 0x34, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0f, 0x31, 0x27, 0x30,
    0x25, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07, 0x30, 0x0e, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02, 0x02, 0x02, 0x00, 0x80, 0x30, 0x07, 0x06,
    0x05, 0x2b, 0x0e, 0x03, 0x02, 0x07,
];

/// BC `SmimeTest.prefBytes`: a recipient key identifier of eight zero octets
/// dated 2007-03-15 17:37:29Z.
const PREFERENCE_ATTRIBUTE: &[u8] = &[
    0x30, 0x2c, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0b, 0x31,
    0x1d, 0xa1, 0x1b, 0x04, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0x18, 0x0f, b'2', b'0', b'0', b'7', b'0',
    b'3', b'1', b'5', b'1', b'7', b'3', b'7', b'2', b'9', b'Z',
];

fn round_trip<T: Decode + Encode + PartialEq + Debug>(value: &T) -> Vec<u8> {
    let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
    let (len, back) = T::decode_der(&der, &DecodingOptions::default()).unwrap();
    assert_eq!(len, der.len());
    assert_eq!(&back, value);
    der
}

fn attribute(oid: tc_asn1::Asn1Oid, value: &impl Encode) -> Vec<u8> {
    let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
    let value = Asn1Object::decode_der(&der, &DecodingOptions::default())
        .unwrap()
        .1;
    Attribute::new(oid, vec![AttributeValue::Other(value)])
        .unwrap()
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap()
}

fn value_of<T: Decode>(attribute: &[u8]) -> T {
    let options = DecodingOptions::default();
    let attribute = Attribute::decode_der(attribute, &options).unwrap().1;
    let der = attribute.values()[0]
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap();
    T::decode_der(&der, &options).unwrap().1
}

#[test]
fn bc_capabilities_attribute_matches_byte_for_byte() {
    let capabilities = SmimeCapabilities::new(vec![
        SmimeCapability::new(SmimeCapabilityId::DES_EDE3_CBC.oid()),
        SmimeCapability::new(SmimeCapabilityId::RC2_CBC.oid())
            .with_parameters(Asn1Any::primitive(tag::INTEGER, &[0, 0x80])),
        SmimeCapability::new(SmimeCapabilityId::DES_CBC.oid()),
    ]);
    assert_eq!(
        attribute(SmimeAttribute::SMIME_CAPABILITIES.oid(), &capabilities),
        CAPABILITIES_ATTRIBUTE
    );
    let back: SmimeCapabilities = value_of(CAPABILITIES_ATTRIBUTE);
    assert_eq!(back, capabilities);
    let rc2 = SmimeCapabilityId::RC2_CBC.oid();
    assert_eq!(back.capabilities_for(&rc2).count(), 1);
}

#[test]
fn bc_encryption_key_preference_attribute_matches_byte_for_byte() {
    let date =
        Asn1GeneralizedTime::decode_der(b"\x18\x0f20070315173729Z", &DecodingOptions::default())
            .unwrap()
            .1;
    let preference = SmimeEncryptionKeyPreference::RecipientKeyId(
        RecipientKeyIdentifier::new(SubjectKeyIdentifier::new(vec![0; 8]).unwrap()).with_date(date),
    );
    assert_eq!(
        attribute(SmimeAttribute::ENCRYP_KEY_PREF.oid(), &preference),
        PREFERENCE_ATTRIBUTE
    );
    assert_eq!(
        value_of::<SmimeEncryptionKeyPreference>(PREFERENCE_ATTRIBUTE),
        preference
    );
}

#[test]
fn every_key_preference_round_trips_under_its_implicit_tag() {
    let key = SubjectKeyIdentifier::new(vec![1, 2, 3]).unwrap();
    let alt = SmimeEncryptionKeyPreference::SubjectAltKeyIdentifier(key);
    assert_eq!(round_trip(&alt), [0x82, 3, 1, 2, 3]);
    let by_issuer = SmimeEncryptionKeyPreference::IssuerAndSerialNumber(
        tc_asn1_cms::signed::IssuerAndSerialNumber::new("CN=CA".parse().unwrap(), 7.into()),
    );
    assert_eq!(round_trip(&by_issuer)[0], 0xa0);
}

#[test]
fn bc_ess_cert_id_v2_omits_the_default_sha256_algorithm() {
    let sha256 = AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse().unwrap());
    let id = EssCertIdV2::new(Asn1OctetString::new(&[0; 32]));
    assert_eq!(id.hash_algorithm(), &sha256);
    let omitted = round_trip(&id);
    assert_eq!(omitted[..4], [0x30, 34, 0x04, 32]);
    assert_eq!(
        round_trip(&id.clone().with_hash_algorithm(sha256.clone())),
        omitted
    );

    let mut written = sha256.encode_to_vec(&EncodingOptions::DER).unwrap();
    written.extend(&omitted[2..]);
    let mut encoding = vec![0x30, written.len() as u8];
    encoding.extend(written);
    let options = DecodingOptions::default();
    assert_eq!(
        EssCertIdV2::decode_der(&encoding, &options),
        Err(Asn1Error::NotDer)
    );
    assert_eq!(EssCertIdV2::decode(&encoding, &options).unwrap().1, id);
}

#[test]
fn a_sha512_ess_cert_id_v2_writes_its_algorithm() {
    let sha512 = AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.3".parse().unwrap());
    let id = EssCertIdV2::new(Asn1OctetString::new(&[0; 64])).with_hash_algorithm(sha512);
    assert_eq!(round_trip(&id)[2], 0x30);
}

#[test]
fn signing_certificates_round_trip_with_and_without_policies() {
    let v1 = SigningCertificate::new(vec![EssCertId::new(Asn1OctetString::new(&[1; 20]))]);
    round_trip(&v1);
    let policy = tc_asn1_x509::ext::PolicyInformation::new("2.5.29.32.0".parse::<tc_asn1::Asn1Oid>().unwrap());
    let v2 = SigningCertificateV2::new(vec![EssCertIdV2::new(Asn1OctetString::new(&[2; 32]))])
        .with_policies(vec![policy]);
    round_trip(&v2);
    assert_eq!(v2.policies().map(<[_]>::len), Some(1));
}

#[test]
fn bc_content_hints_round_trip_with_and_without_a_description() {
    let content_type: tc_asn1::Asn1Oid = "1.2.2.3".parse().unwrap();
    let hints = ContentHints::new(content_type.clone());
    round_trip(&hints);
    let described = hints.with_content_description(Asn1Utf8String::new("Description"));
    round_trip(&described);
    assert_eq!(described.content_type(), &content_type);
}

#[test]
fn attribute_tables_name_the_id_aa_arc() {
    assert_eq!(
        EssAttribute::SIGNING_CERTIFICATE_V2.dotted(),
        "1.2.840.113549.1.9.16.2.47"
    );
    assert_eq!(
        SmimeAttribute::ENCRYP_KEY_PREF.dotted(),
        "1.2.840.113549.1.9.16.2.11"
    );
}
