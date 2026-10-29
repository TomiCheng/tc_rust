use tc_asn1::{Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_ocsp::{
    BasicOcspResponse, CertStatus, OcspId, OcspRequest, OcspResponse, OcspResponseStatus,
    ResponderId, ResponseBytes,
};

const UNSIGNED_REQUEST: &[u8] = include_bytes!("data/unsigned_request.der");
const SIGNED_REQUEST: &[u8] = include_bytes!("data/signed_request.der");
const RESPONSE: &[u8] = include_bytes!("data/response.der");

fn der<T: Decode>(bytes: &[u8]) -> T {
    let (len, value) = T::decode_der(bytes, &DecodingOptions::default()).unwrap();
    assert_eq!(len, bytes.len());
    value
}

#[test]
fn bc_requests_round_trip_byte_for_byte() -> Result<(), Asn1Error> {
    for encoding in [UNSIGNED_REQUEST, SIGNED_REQUEST] {
        let request: OcspRequest = der(encoding);
        assert_eq!(request.encode_to_vec(&EncodingOptions::DER)?, encoding);
    }
    Ok(())
}

#[test]
fn bc_signed_request_carries_its_signer_certificate() {
    let request: OcspRequest = der(SIGNED_REQUEST);
    let signature = request.optional_signature().unwrap();
    assert_eq!(signature.certs().map(<[_]>::len), Some(1));
    assert!(
        der::<OcspRequest>(UNSIGNED_REQUEST)
            .optional_signature()
            .is_none()
    );
    assert_eq!(request.tbs_request().request_list().len(), 1);
    assert_eq!(request.tbs_request().version(), 0.into());
}

#[test]
fn bc_response_rebuilt_from_its_basic_response_encodes_the_same() -> Result<(), Asn1Error> {
    let response: OcspResponse = der(RESPONSE);
    assert_eq!(*response.response_status(), OcspResponseStatus::Successful);
    let bytes = response.response_bytes().unwrap();
    assert_eq!(*bytes.response_type(), OcspId::BASIC.oid());

    let basic: BasicOcspResponse = der(bytes.response().as_bytes());
    let data = basic.tbs_response_data();
    assert!(matches!(data.responder_id(), ResponderId::ByName(_)));
    assert!(matches!(data.responses()[0].cert_status(), CertStatus::Revoked(_)));

    let rebuilt =
        OcspResponse::new(*response.response_status()).with_response_bytes(ResponseBytes::new(
            bytes.response_type().clone(),
            Asn1OctetString::new(&basic.encode_to_vec(&EncodingOptions::DER)?),
        ));
    assert_eq!(rebuilt.encode_to_vec(&EncodingOptions::DER)?, RESPONSE);
    Ok(())
}
