use std::fmt::Debug;

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Ia5String, Asn1OctetString, Decode, DecodingOptions,
    Encode, EncodingOptions,
};
use tc_asn1_ocsp::{
    CertId, CertStatus, CrlId, OcspId, OcspResponse, OcspResponseStatus, Request, ResponderId,
    ResponseData, RevokedInfo, ServiceLocator, SingleResponse, TbsRequest,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::crl::CrlReason;

fn round_trip<T: Decode + Encode + PartialEq + Debug>(value: &T) -> Vec<u8> {
    let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
    let (len, back) = T::decode_der(&der, &DecodingOptions::default()).unwrap();
    assert_eq!(len, der.len());
    assert_eq!(&back, value);
    der
}

fn time() -> Asn1GeneralizedTime {
    Asn1GeneralizedTime::decode_der(b"\x18\x0f20261029000000Z", &DecodingOptions::default())
        .unwrap()
        .1
}

fn cert_id() -> CertId {
    CertId::new(
        AlgorithmIdentifier::with_null("1.3.14.3.2.26".parse().unwrap()),
        Asn1OctetString::new(&[1; 20]),
        Asn1OctetString::new(&[2; 20]),
        7.into(),
    )
}

#[test]
fn every_certificate_status_round_trips_under_its_implicit_tag() {
    let revoked = RevokedInfo::new(time()).with_revocation_reason(CrlReason::KeyCompromise);
    for (status, first) in [
        (CertStatus::Good, 0x80),
        (CertStatus::from(revoked), 0xa1),
        (CertStatus::Unknown, 0x82),
    ] {
        assert_eq!(round_trip(&status)[0], first);
    }
}

#[test]
fn null_statuses_with_contents_and_unknown_tags_are_rejected() {
    let options = DecodingOptions::default();
    assert_eq!(
        CertStatus::decode_der(&[0x80, 1, 0], &options),
        Err(Asn1Error::MalformedValue)
    );
    assert_eq!(
        CertStatus::decode_der(&[0x83, 0], &options),
        Err(Asn1Error::UnexpectedTag)
    );
}

#[test]
fn responder_ids_wrap_their_alternative_in_an_explicit_tag() {
    let by_name = ResponderId::from("CN=Responder".parse::<tc_asn1_x500::Name>().unwrap());
    assert_eq!(round_trip(&by_name)[0], 0xa1);
    let by_key = ResponderId::ByKey(Asn1OctetString::new(&[3; 20]));
    assert_eq!(round_trip(&by_key)[..4], [0xa2, 22, 4, 20]);
}

#[test]
fn a_written_v1_version_is_kept_so_signatures_still_verify() {
    let request = TbsRequest::new(vec![Request::new(cert_id())]);
    let omitted = round_trip(&request);
    let written = round_trip(&request.clone().with_version(0.into()));
    assert_eq!(written.len(), omitted.len() + 5);
    assert_eq!(written[2..7], [0xa0, 3, 2, 1, 0]);
}

#[test]
fn response_data_round_trips_with_optional_fields() {
    let single = SingleResponse::new(cert_id(), CertStatus::Good, time()).with_next_update(time());
    let data = ResponseData::new(
        ResponderId::ByKey(Asn1OctetString::new(&[3; 20])),
        time(),
        vec![single],
    );
    round_trip(&data);
    assert_eq!(data.version(), 0.into());
}

#[test]
fn an_error_status_is_sent_without_response_bytes() {
    let response = OcspResponse::new(OcspResponseStatus::TryLater);
    assert_eq!(round_trip(&response), [0x30, 3, 0x0a, 1, 3]);
    assert_eq!(
        OcspResponse::decode_der(&[0x30, 3, 0x0a, 1, 4], &DecodingOptions::default()),
        Err(Asn1Error::MalformedValue)
    );
}

#[test]
fn crl_references_and_service_locators_round_trip() {
    assert_eq!(round_trip(&CrlId::new()), [0x30, 0]);
    round_trip(
        &CrlId::new()
            .with_crl_url(Asn1Ia5String::new("http://crl.example/ca.crl").unwrap())
            .with_crl_num(42.into())
            .with_crl_time(time()),
    );
    round_trip(&ServiceLocator::new("CN=CA".parse().unwrap()));
}

#[test]
fn ocsp_identifiers_sit_under_id_pkix_ocsp() {
    assert_eq!(OcspId::NONCE.dotted(), "1.3.6.1.5.5.7.48.1.2");
    assert_eq!(OcspId::from_oid(&OcspId::BASIC.oid()), Some(OcspId::BASIC));
}
