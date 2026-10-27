//! Test data shared across modules: the RFC 8410 example certificate, a
//! minimal CRL, algorithm identifiers and signers.

use alloc::vec;

use tc_asn1::{Asn1BitString, Asn1OctetString, Decode, DecodingOptions};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::{Certificate, Time, Version};
use tc_asn1_x509::crl::{CertificateList, TbsCertList};
use tc_asn1_x509::ext::SubjectKeyIdentifier;

use crate::content::CertificateChoices;
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
