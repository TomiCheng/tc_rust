use std::sync::Arc;

use chrono::{TimeDelta, Utc};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder, Params};
use tc_asn1::{Asn1GeneralizedTime, Asn1OctetString, Encode, EncodingOptions};
use tc_asn1_ocsp::{
    CertId, CertStatus, OcspResponse, OcspResponseStatus, ResponderId, ResponseData, SingleResponse,
};
use tc_asn1_x509::{
    alg::AlgorithmIdentifier,
    ext::{ExtendedKeyUsage, Extension, ExtensionId, Extensions, KeyPurposeId},
    name::GeneralName,
};
use tc_ocsp::{
    OcspError, ResponseValidation, basic_response, certificate_id, decode_request, decode_response,
    nonce_extension, request_for, sign_request, sign_response, verify_request_signature,
};
use tc_x509::{
    DefaultX509OperatorBuilder, X509Operator, X509OperatorBuilder,
    cert::X509V3CertificateGenerator, extension::key_identifier_of,
};

fn key_pair(oper: &dyn X509Operator) -> (Box<dyn Params>, Arc<dyn Params>) {
    let mut generator = oper.key_pair_generator().get_by_name("Ed25519").unwrap();
    let (public, private) = generator.generate().unwrap().into_parts();
    (public, private.into())
}

#[test]
fn signed_request_round_trip_verifies_with_the_requestor_key() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (public, private) = key_pair(&*x509);
    let mut certificate = X509V3CertificateGenerator::new();
    certificate.set_subject_by_str("CN=Requestor").unwrap();
    certificate.set_issuer_by_str("CN=Requestor").unwrap();
    certificate.set_validity_days(365).unwrap();
    certificate.set_subject_public_key_info(x509.spki().encode(&*public).unwrap());
    let factory = x509.signature_factory("Ed25519", private).unwrap();
    let certificate = certificate.generate(&*factory).unwrap();

    let algo = DefaultAlgoBuilder::default().build();
    let sha256 = "2.16.840.1.101.3.4.2.1".parse().unwrap();
    let id = certificate_id(&certificate, &certificate, &sha256, algo.digest()).unwrap();
    let nonce = [0x5a; 32];
    let request = request_for(id, Some(&nonce)).unwrap();
    let tbs = request
        .tbs_request()
        .clone()
        .with_requestor_name(GeneralName::DirectoryName(certificate.subject().clone()));
    let signed = sign_request(tbs, &*factory, vec![certificate.certificate().clone()]).unwrap();
    let mut bytes = signed.encode_to_vec(&EncodingOptions::DER).unwrap();
    let parsed = decode_request(&bytes).unwrap();
    let verifier = x509.verifier_factory_provider(public.into());
    verify_request_signature(&parsed, &*verifier).unwrap();

    let (other, _) = key_pair(&*x509);
    let wrong_verifier = x509.verifier_factory_provider(other.into());
    assert!(matches!(
        verify_request_signature(&parsed, &*wrong_verifier),
        Err(OcspError::InvalidSignature)
    ));
    bytes.push(0);
    assert!(decode_request(&bytes).is_err());
}

#[test]
fn response_validation_binds_the_status_to_the_issuer_nonce_and_time() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (public, private) = key_pair(&*x509);
    let ca_factory = x509.signature_factory("Ed25519", private).unwrap();
    let mut generator = X509V3CertificateGenerator::new();
    generator.set_subject_by_str("CN=Issuer").unwrap();
    generator.set_issuer_by_str("CN=Issuer").unwrap();
    generator.set_validity_days(365).unwrap();
    generator.set_subject_public_key_info(x509.spki().encode(&*public).unwrap());
    generator.set_serial_number(1.into()).unwrap();
    let issuer = generator.generate(&*ca_factory).unwrap();

    let (leaf_key, _) = key_pair(&*x509);
    generator.set_subject_by_str("CN=Leaf").unwrap();
    generator.set_subject_public_key_info(x509.spki().encode(&*leaf_key).unwrap());
    generator.set_serial_number(2.into()).unwrap();
    let leaf = generator.generate(&*ca_factory).unwrap();

    let algo = DefaultAlgoBuilder::default().build();
    let sha256 = "2.16.840.1.101.3.4.2.1".parse().unwrap();
    let id = certificate_id(&leaf, &issuer, &sha256, algo.digest()).unwrap();
    let now = Utc::now();
    let this_update = Asn1GeneralizedTime::try_from(now - TimeDelta::minutes(2)).unwrap();
    let next_update = Asn1GeneralizedTime::try_from(now + TimeDelta::minutes(10)).unwrap();
    let produced_at = Asn1GeneralizedTime::try_from(now - TimeDelta::minutes(1)).unwrap();
    let unknown_hash = AlgorithmIdentifier::new("1.3.6.1.4.1.32473.1".parse().unwrap());
    let unsupported_id = CertId::new(
        unknown_hash,
        id.issuer_name_hash().clone(),
        id.issuer_key_hash().clone(),
        id.serial_number().clone(),
    );
    let unsupported = SingleResponse::new(unsupported_id, CertStatus::Unknown, this_update);
    let entry =
        SingleResponse::new(id, CertStatus::Good, this_update).with_next_update(next_update);
    let responder_id = ResponderId::ByKey(Asn1OctetString::new(&key_identifier_of(
        issuer.subject_public_key_info(),
    )));
    let nonce = [0xe7; 32];
    let data = ResponseData::new(responder_id, produced_at, vec![unsupported, entry])
        .with_response_extensions(Extensions::new(vec![nonce_extension(&nonce).unwrap()]).unwrap());
    let signed = sign_response(data, &*ca_factory, vec![]).unwrap();
    let parsed = decode_response(&signed.encode_to_vec(&EncodingOptions::DER).unwrap()).unwrap();
    let response = basic_response(&parsed).unwrap();
    let policy = ResponseValidation::new(now, TimeDelta::minutes(5)).with_expected_nonce(&nonce);
    assert_eq!(policy.at(), now);
    assert_eq!(policy.max_age(), TimeDelta::minutes(5));
    assert_eq!(policy.expected_nonce(), Some(nonce.as_slice()));

    let status = policy
        .validate(&response, &leaf, &issuer, &issuer, algo.digest(), &*x509)
        .unwrap();
    assert_eq!(status.cert_status(), &CertStatus::Good);
    assert_eq!(status, &response.tbs_response_data().responses()[1]);
    assert!(matches!(
        policy.validate(&response, &issuer, &issuer, &issuer, algo.digest(), &*x509),
        Err(OcspError::CertificateMismatch)
    ));
    assert!(matches!(
        policy.validate(&response, &leaf, &issuer, &leaf, algo.digest(), &*x509),
        Err(OcspError::UnauthorizedResponder)
    ));
    let policy = ResponseValidation::new(now + TimeDelta::minutes(11), policy.max_age())
        .with_expected_nonce(&nonce);
    assert!(matches!(
        policy.validate(&response, &leaf, &issuer, &issuer, algo.digest(), &*x509),
        Err(OcspError::InvalidTime)
    ));
    let policy = ResponseValidation::new(now, policy.max_age()).with_expected_nonce(&[0; 32]);
    assert!(matches!(
        policy.validate(&response, &leaf, &issuer, &issuer, algo.digest(), &*x509),
        Err(OcspError::NonceMismatch)
    ));
    let (responder_public, responder_private) = key_pair(&*x509);
    let responder_factory = x509
        .signature_factory("Ed25519", responder_private)
        .unwrap();
    generator.set_subject_by_str("CN=Responder").unwrap();
    generator.set_subject_public_key_info(x509.spki().encode(&*responder_public).unwrap());
    generator
        .set_validity_by_datetime(now - TimeDelta::days(1), now + TimeDelta::days(1))
        .unwrap();
    generator.set_serial_number(3.into()).unwrap();
    let without_eku = generator.generate(&*ca_factory).unwrap();
    let eku = ExtendedKeyUsage::new(vec![KeyPurposeId::OCSP_SIGNING.oid()])
        .unwrap()
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap();
    generator
        .add_extension(Extension::new(
            ExtensionId::EXT_KEY_USAGE.oid(),
            false,
            &eku,
        ))
        .unwrap();
    generator.set_serial_number(4.into()).unwrap();
    let delegated = generator.generate(&*ca_factory).unwrap();

    let delegated_data = ResponseData::new(
        ResponderId::ByName(delegated.subject().clone()),
        *response.tbs_response_data().produced_at(),
        response.tbs_response_data().responses().to_vec(),
    );
    let signed = sign_response(
        delegated_data,
        &*responder_factory,
        vec![delegated.certificate().clone()],
    )
    .unwrap();
    let delegated_response = basic_response(&signed).unwrap();
    let policy = ResponseValidation::new(now, policy.max_age());
    assert!(
        policy
            .validate(
                &delegated_response,
                &leaf,
                &issuer,
                &delegated,
                algo.digest(),
                &*x509
            )
            .is_ok()
    );
    assert!(matches!(
        policy.validate(
            &delegated_response,
            &leaf,
            &issuer,
            &without_eku,
            algo.digest(),
            &*x509
        ),
        Err(OcspError::UnauthorizedResponder)
    ));
    assert!(matches!(
        basic_response(&OcspResponse::new(OcspResponseStatus::TryLater)),
        Err(OcspError::ResponseStatus(OcspResponseStatus::TryLater))
    ));
}
