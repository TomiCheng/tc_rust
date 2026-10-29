use std::fmt::Debug;

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1PrintableString, Decode, DecodingOptions, Encode,
    EncodingOptions,
};
use tc_asn1_icao::{CscaMasterList, DataGroupHash, IcaoId, LdsSecurityObject, LdsVersionInfo};
use tc_asn1_x509::alg::AlgorithmIdentifier;

const MASTER_LIST: &[u8] = include_bytes!("data/masterlist_content.der");

fn round_trip<T: Decode + Encode + PartialEq + Debug>(value: &T) -> Vec<u8> {
    let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
    assert_eq!(
        T::decode_der(&der, &DecodingOptions::default()).unwrap().1,
        *value
    );
    der
}

fn sha256() -> AlgorithmIdentifier {
    AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse().unwrap())
}

fn hashes(count: u8) -> Vec<DataGroupHash> {
    (1..=count)
        .map(|n| DataGroupHash::new(n.into(), Asn1OctetString::new(&[n; 32])))
        .collect()
}

fn version_info() -> LdsVersionInfo {
    LdsVersionInfo::new(
        Asn1PrintableString::new("Hello").unwrap(),
        Asn1PrintableString::new("world").unwrap(),
    )
}

#[test]
fn bc_master_list_round_trips_byte_for_byte() {
    let list = CscaMasterList::decode_der(MASTER_LIST, &DecodingOptions::default())
        .unwrap()
        .1;
    assert_eq!(list.version(), 0.into());
    assert_eq!(list.cert_list().len(), 3);
    assert_eq!(
        list.encode_to_vec(&EncodingOptions::DER).unwrap(),
        MASTER_LIST
    );
}

#[test]
fn bc_security_object_is_version_1_only_with_version_info() {
    let object = LdsSecurityObject::new(sha256(), hashes(2)).unwrap();
    assert_eq!(object.version(), 0.into());
    round_trip(&object);
    let object = object.with_lds_version_info(version_info());
    assert_eq!(object.version(), 1.into());
    let mut der = round_trip(&object);

    assert_eq!(der[2..5], [2, 1, 1]);
    der[4] = 0;
    assert_eq!(
        LdsSecurityObject::decode_der(&der, &DecodingOptions::default()),
        Err(Asn1Error::MalformedValue)
    );
}

#[test]
fn bc_security_object_takes_2_to_16_data_groups() {
    assert_eq!(
        LdsSecurityObject::new(sha256(), hashes(1)),
        Err(Asn1Error::MalformedValue)
    );
    assert_eq!(
        LdsSecurityObject::new(sha256(), hashes(17)),
        Err(Asn1Error::MalformedValue)
    );
    round_trip(&LdsSecurityObject::new(sha256(), hashes(16)).unwrap());
}

#[test]
fn bc_data_group_hash_round_trips() {
    let hash = DataGroupHash::new(1.into(), Asn1OctetString::new(&[0xab; 20]));
    assert_eq!(round_trip(&hash)[..5], [0x30, 25, 2, 1, 1]);
}

#[test]
fn icao_content_types_sit_under_mrtd_security() {
    assert_eq!(IcaoId::LDS_SECURITY_OBJECT.dotted(), "2.23.136.1.1.1");
    assert_eq!(
        IcaoId::from_oid(&IcaoId::CSCA_MASTER_LIST.oid()),
        Some(IcaoId::CSCA_MASTER_LIST)
    );
}
