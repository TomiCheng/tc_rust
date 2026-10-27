//! Test data shared across modules: the RFC 8410 example certificate, a
//! minimal CRL, algorithm identifiers and signers.

use alloc::vec;
use alloc::vec::Vec;

use tc_asn1::{
    Asn1Any, Asn1BitString, Asn1GeneralizedTime, Asn1Object, Asn1OctetString, Asn1Oid, Decode,
    DecodingOptions, tag,
};
use tc_asn1_x500::{Attribute, AttributeValue, DirectoryString};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::attr::{
    AttCertValidityPeriod, AttributeCertificate, AttributeCertificateInfo, Holder, V2Form,
};
use tc_asn1_x509::cert::{Certificate, Time, Version};
use tc_asn1_x509::crl::{CertificateList, TbsCertList};
use tc_asn1_x509::ext::SubjectKeyIdentifier;
use tc_asn1_x509::name::{GeneralName, GeneralNames};

use crate::content::{
    CertificateChoices, ContentType, EncryptedContentInfo, OtherCertificateFormat,
};
use crate::recipient::{
    KekIdentifier, KekRecipientInfo, KeyAgreeRecipientInfo, KeyTransRecipientInfo,
    OriginatorPublicKey, OtherRecipientInfo, PasswordRecipientInfo, RecipientEncryptedKey,
    RecipientIdentifier, RecipientInfo,
};
use crate::signed::{IssuerAndSerialNumber, SignerInfo};

pub(crate) const RFC_8410: &[u8] = include_bytes!("../tests/data/rfc8410.der");

/// An empty v1 CRL with an Ed25519 signature algorithm, as tc_asn1_x509 tests it.
pub(crate) const CRL: &[u8] = &[
    0x30, 0x25, 0x30, 0x18, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 0x30, 0, 0x17, 13, b'2', b'6', b'0',
    b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z', 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 3,
    2, 0, 0xaa,
];

pub(crate) fn certificate() -> CertificateChoices {
    Certificate::decode(RFC_8410, &DecodingOptions::default())
        .unwrap()
        .1
        .into()
}

pub(crate) fn crl() -> CertificateList {
    let tbs = TbsCertList::new(
        Version::V1,
        AlgorithmIdentifier::new("1.3.101.112".parse().unwrap()),
        "".parse().unwrap(),
        Time::new(2026, 1, 1, 0, 0, 0).unwrap(),
    )
    .unwrap();
    CertificateList::new(tbs, Asn1BitString::from_bytes(&[0xaa])).unwrap()
}

pub(crate) fn sha256() -> AlgorithmIdentifier {
    AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse().unwrap())
}

pub(crate) fn ed25519() -> AlgorithmIdentifier {
    AlgorithmIdentifier::new("1.3.101.112".parse().unwrap())
}

pub(crate) fn by_issuer() -> SignerInfo {
    SignerInfo::new(
        IssuerAndSerialNumber::new("CN=Signer".parse().unwrap(), 1.into()).into(),
        sha256(),
        ed25519(),
        Asn1OctetString::new(&[0x5a; 64]),
    )
}

pub(crate) fn by_key_identifier() -> SignerInfo {
    SignerInfo::new(
        SubjectKeyIdentifier::new(vec![9; 20]).unwrap().into(),
        sha256(),
        ed25519(),
        Asn1OctetString::new(&[0x5a; 64]),
    )
}

pub(crate) fn alg(dotted: &str) -> AlgorithmIdentifier {
    AlgorithmIdentifier::new(dotted.parse().unwrap())
}

pub(crate) fn attribute() -> Attribute {
    let value = AttributeValue::from(Asn1Object::OctetString(Asn1OctetString::new(&[1])));
    Attribute::new("1.2.3.4".parse::<Asn1Oid>().unwrap(), vec![value]).unwrap()
}

pub(crate) fn attribute_certificate() -> AttributeCertificate {
    let names = GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap();
    let start = Asn1GeneralizedTime::new(2026, 1, 1, 0, 0, 0).unwrap();
    let end = Asn1GeneralizedTime::new(2027, 1, 1, 0, 0, 0).unwrap();
    let info = AttributeCertificateInfo::new(
        Holder::new(None, Some(names.clone()), None).unwrap(),
        V2Form::new(Some(names), None, None).unwrap().into(),
        alg("1.2.3"),
        1.into(),
        AttCertValidityPeriod::new(start, end).unwrap(),
        vec![
            Attribute::new(
                "1.2.3".parse::<Asn1Oid>().unwrap(),
                vec![DirectoryString::new("x").unwrap().into()],
            )
            .unwrap(),
        ],
    )
    .unwrap();
    AttributeCertificate::new(info, Asn1BitString::from_bytes(&[0xaa])).unwrap()
}

pub(crate) fn other_certificate() -> CertificateChoices {
    CertificateChoices::Other(OtherCertificateFormat::new(
        "1.2.3".parse().unwrap(),
        Asn1Any::primitive(tag::OCTET_STRING, b"x"),
    ))
}

pub(crate) fn encrypted_content() -> EncryptedContentInfo {
    EncryptedContentInfo::new(ContentType::DATA.oid(), alg("2.16.840.1.101.3.4.1.42"))
        .with_encrypted_content(Asn1OctetString::new(&[0xc1; 32]))
}

pub(crate) fn by_issuer_rid() -> RecipientIdentifier {
    IssuerAndSerialNumber::new("CN=Recipient".parse().unwrap(), 2.into()).into()
}

pub(crate) fn key_trans() -> KeyTransRecipientInfo {
    KeyTransRecipientInfo::new(
        by_issuer_rid(),
        alg("1.2.840.113549.1.1.7"),
        Asn1OctetString::new(&[0x77; 32]),
    )
}

pub(crate) fn key_agree() -> KeyAgreeRecipientInfo {
    KeyAgreeRecipientInfo::new(
        OriginatorPublicKey::new(
            alg("1.2.840.10045.2.1"),
            Asn1BitString::from_bytes(&[4; 65]),
        )
        .into(),
        alg("1.3.132.1.11.1"),
        vec![RecipientEncryptedKey::new(
            IssuerAndSerialNumber::new("CN=Recipient".parse().unwrap(), 2.into()).into(),
            Asn1OctetString::new(&[0x55; 24]),
        )],
    )
}

pub(crate) fn kek() -> KekRecipientInfo {
    KekRecipientInfo::new(
        KekIdentifier::new(Asn1OctetString::new(b"kek-1")),
        alg("2.16.840.1.101.3.4.1.5"),
        Asn1OctetString::new(&[0x66; 24]),
    )
}

pub(crate) fn password() -> PasswordRecipientInfo {
    PasswordRecipientInfo::new(
        alg("1.2.840.113549.1.9.16.3.9"),
        Asn1OctetString::new(&[0x88; 24]),
    )
}

/// One recipient of each kind: key transport, key agreement, KEK, password and other.
pub(crate) fn recipients() -> Vec<RecipientInfo> {
    vec![
        key_trans().into(),
        key_agree().into(),
        kek().into(),
        password().into(),
        OtherRecipientInfo::new(
            OtherRecipientInfo::ID_ORI_KEM.oid(),
            Asn1Any::primitive(tag::OCTET_STRING, b"kem"),
        )
        .into(),
    ]
}
