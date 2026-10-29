use tc_asn1::{Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_cmp::{PkiFailureInfo, PkiStatus};
use tc_asn1_cms::content::SignedData;
use tc_asn1_tsp::{TimeStampReq, TimeStampResp, TstInfo};

const SHA1_REQUEST: &[u8] = include_bytes!("data/sha1_request.der");
const RIPEMD160_REQUEST: &[u8] = include_bytes!("data/ripemd160_request.der");
const SHA1_RESPONSE: &[u8] = include_bytes!("data/sha1_response.der");
const UNACCEPTABLE_POLICY: &[u8] = include_bytes!("data/unacceptable_policy.der");
const GENERALIZED_TIME: &[u8] = include_bytes!("data/generalized_time.der");
const V2_SIGNING_CERT_RESPONSE: &[u8] = include_bytes!("data/v2_signing_cert_response.der");

fn der<T: Decode>(bytes: &[u8]) -> T {
    let (len, value) = T::decode_der(bytes, &DecodingOptions::default()).unwrap();
    assert_eq!(len, bytes.len());
    value
}

fn round_trip<T: Decode + Encode>(bytes: &[u8]) -> T {
    let value: T = der(bytes);
    assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), bytes);
    value
}

/// The `TSTInfo` inside a granted response's `SignedData`.
fn tst_info(response: &TimeStampResp) -> TstInfo {
    let token = response.time_stamp_token().unwrap();
    let signed: SignedData = der(token.content().unwrap().raw());
    let content = signed.encap_content_info().content().unwrap();
    der(der::<Asn1OctetString>(content.raw()).as_bytes())
}

#[test]
fn bc_requests_round_trip_byte_for_byte() {
    let request: TimeStampReq = round_trip(SHA1_REQUEST);
    assert_eq!(request.version(), 1.into());
    assert!(request.nonce().is_some());
    assert!(!request.cert_req());

    let request: TimeStampReq = round_trip(RIPEMD160_REQUEST);
    assert!(request.cert_req());
    assert_eq!(
        request.req_policy().unwrap().to_string(),
        "1.3.6.1.4.1.5255.5.1"
    );
}

#[test]
fn bc_granted_responses_round_trip_and_hold_a_tst_info() {
    for encoding in [SHA1_RESPONSE, V2_SIGNING_CERT_RESPONSE] {
        let response: TimeStampResp = round_trip(encoding);
        assert_eq!(*response.status().status(), PkiStatus::Granted);
        let info = tst_info(&response);
        assert_eq!(info.version(), 1.into());
        let reencoded = info.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(der::<TstInfo>(&reencoded), info);
    }
}

/// tc_asn1's GeneralizedTime follows the RFC 5280 profile, which forbids
/// fractional seconds; RFC 3161 allows them in `genTime`.
#[test]
fn bc_tst_info_with_fractional_seconds_is_rejected_by_the_rfc_5280_time_profile() {
    let response: TimeStampResp = round_trip(GENERALIZED_TIME);
    let token = response.time_stamp_token().unwrap();
    let signed: SignedData = der(token.content().unwrap().raw());
    let content = der::<Asn1OctetString>(signed.encap_content_info().content().unwrap().raw());
    assert_eq!(
        TstInfo::decode_der(content.as_bytes(), &DecodingOptions::default()).unwrap_err(),
        Asn1Error::MalformedValue
    );
}

#[test]
fn bc_rejection_names_the_unaccepted_policy() -> Result<(), Asn1Error> {
    let response: TimeStampResp = round_trip(UNACCEPTABLE_POLICY);
    let status = response.status();
    assert_eq!(*status.status(), PkiStatus::Rejection);
    assert_eq!(
        status.status_string().unwrap().strings()[0].as_str(),
        "Requested policy is not supported."
    );
    assert_eq!(status.fail_info(), Some(&PkiFailureInfo::UNACCEPTED_POLICY));
    assert!(response.time_stamp_token().is_none());
    Ok(())
}
