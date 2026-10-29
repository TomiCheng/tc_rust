use std::fmt::Debug;

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1GeneralizedTime, Asn1OctetString, Asn1Oid, Decode, DecodingOptions,
    Encode, EncodingOptions, tag,
};
use tc_asn1_cmp::{PkiStatus, PkiStatusInfo};
use tc_asn1_cms::content::{ContentInfo, ContentType};
use tc_asn1_tsp::{
    Accuracy, ArchiveTimeStamp, ArchiveTimeStampChain, ArchiveTimeStampSequence, CryptoInfos,
    EncryptionInfo, EvidenceRecord, MessageImprint, PartialHashtree, TimeStampReq, TimeStampResp,
    TstInfo,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

fn round_trip<T: Decode + Encode + PartialEq + Debug>(value: &T) -> Vec<u8> {
    let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
    let (len, back) = T::decode_der(&der, &DecodingOptions::default()).unwrap();
    assert_eq!(len, der.len());
    assert_eq!(&back, value);
    der
}

fn sha256() -> AlgorithmIdentifier {
    AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse().unwrap())
}

fn imprint() -> MessageImprint {
    MessageImprint::new(sha256(), Asn1OctetString::new(&[0xab; 32]))
}

fn policy() -> Asn1Oid {
    "1.2.3.4.1".parse().unwrap()
}

fn time() -> Asn1GeneralizedTime {
    Asn1GeneralizedTime::decode_der(b"\x18\x0f20261029120000Z", &DecodingOptions::default())
        .unwrap()
        .1
}

fn token() -> ContentInfo {
    ContentInfo::new(ContentType::SIGNED_DATA.oid())
}

#[test]
fn accuracy_rejects_sub_second_fields_outside_1_to_999() {
    let accuracy = Accuracy::new()
        .with_seconds(1.into())
        .with_millis(500.into())
        .unwrap()
        .with_micros(999.into())
        .unwrap();
    assert_eq!(
        round_trip(&accuracy),
        [0x30, 11, 2, 1, 1, 0x80, 2, 1, 0xf4, 0x81, 2, 3, 0xe7]
    );
    assert_eq!(
        Accuracy::new().with_millis(0.into()),
        Err(Asn1Error::MalformedValue)
    );
    assert_eq!(
        Accuracy::new().with_micros(1000.into()),
        Err(Asn1Error::MalformedValue)
    );
    assert_eq!(
        Accuracy::decode_der(&[0x30, 3, 0x80, 1, 0], &DecodingOptions::default()),
        Err(Asn1Error::MalformedValue)
    );
}

#[test]
fn cert_req_is_written_only_when_true_and_a_written_false_is_not_der() {
    let request = TimeStampReq::new(imprint());
    let omitted = round_trip(&request);
    let asked = round_trip(&request.clone().with_cert_req(true));
    assert!(asked.ends_with(&[1, 1, 0xff]));

    let mut written = omitted[2..].to_vec();
    written.extend([1, 1, 0]);
    let mut encoding = vec![0x30, written.len() as u8];
    encoding.extend(written);
    let options = DecodingOptions::default();
    assert_eq!(
        TimeStampReq::decode_der(&encoding, &options),
        Err(Asn1Error::NotDer)
    );
    assert_eq!(
        TimeStampReq::decode(&encoding, &options).unwrap().1,
        request
    );
}

#[test]
fn tst_info_round_trips_with_every_option() {
    let info = TstInfo::new(policy(), imprint(), 0x502f.into(), time())
        .with_accuracy(Accuracy::new().with_seconds(1.into()))
        .with_ordering(true)
        .with_nonce(100.into())
        .with_tsa(tc_asn1_x509::name::GeneralName::DirectoryName(
            "CN=TSA".parse().unwrap(),
        ));
    round_trip(&info);
    assert!(info.ordering());
    assert_eq!(info.version(), 1.into());
}

#[test]
fn a_granted_response_carries_its_token() {
    let response =
        TimeStampResp::new(PkiStatusInfo::new(PkiStatus::Granted)).with_time_stamp_token(token());
    round_trip(&response);
}

#[test]
fn evidence_records_nest_chains_of_archive_time_stamps() {
    let tree = PartialHashtree::new(vec![Asn1OctetString::new(&[1; 32])]);
    let stamp = ArchiveTimeStamp::new(token())
        .with_digest_algorithm(sha256())
        .with_reduced_hashtree(vec![tree]);
    let der = round_trip(&stamp);
    assert_eq!(der[2], 0xa0);

    let sequence =
        ArchiveTimeStampSequence::new(vec![ArchiveTimeStampChain::new(vec![stamp.clone()])]);
    let record =
        EvidenceRecord::new(vec![sha256()], sequence).with_encryption_info(EncryptionInfo::new(
            "1.2.3.4.2".parse().unwrap(),
            Asn1Any::primitive(tag::NULL, &[]),
        ));
    round_trip(&record);
    assert_eq!(
        record.archive_time_stamp_sequence().chains()[0].archive_time_stamps(),
        [stamp]
    );
}

#[test]
fn evidence_records_other_than_version_1_are_rejected() {
    let record = EvidenceRecord::new(vec![], ArchiveTimeStampSequence::new(vec![]));
    let mut der = round_trip(&record);
    assert_eq!(der[2..5], [2, 1, 1]);
    der[4] = 2;
    assert_eq!(
        EvidenceRecord::decode_der(&der, &DecodingOptions::default()),
        Err(Asn1Error::MalformedValue)
    );
}

#[test]
fn crypto_infos_need_at_least_one_attribute() {
    assert_eq!(CryptoInfos::new(vec![]), Err(Asn1Error::MalformedValue));
    assert_eq!(
        CryptoInfos::decode_der(&[0x30, 0], &DecodingOptions::default()),
        Err(Asn1Error::MalformedValue)
    );
}

#[test]
fn request_extensions_go_under_an_implicit_context_zero() {
    let nonce = tc_asn1_x509::ext::Extension::new(
        "1.3.6.1.5.5.7.48.1.2".parse::<Asn1Oid>().unwrap(),
        false,
        &[4, 1, 7],
    );
    let extensions = tc_asn1_x509::ext::Extensions::new(vec![nonce]).unwrap();
    let request = TimeStampReq::new(imprint()).with_extensions(extensions);
    let der = round_trip(&request);
    let at = der.iter().rposition(|&b| b == 0xa0).unwrap();
    assert_eq!(der[at + 2], 0x30);
}
