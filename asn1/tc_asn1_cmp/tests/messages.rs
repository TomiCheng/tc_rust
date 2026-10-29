use std::fmt::Debug;

use tc_asn1::{
    Asn1Any, Asn1Boolean, Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions,
    tag,
};
use tc_asn1_cmp::crmf::{
    CertReqMessages, CertReqMsg, CertRequest, CertTemplate, Controls, CrmfId, PkiArchiveOptions,
    PopoPrivKey, ProofOfPossession, SubsequentMessage,
};
use tc_asn1_cmp::{
    CertRepMessage, CmpCertificate, CmpId, ErrorMsgContent, GenMsgContent, InfoTypeAndValue,
    PbmParameter, PkiBody, PkiHeader, PkiMessage, PkiMessages, PkiStatus, PkiStatusInfo, PollRep,
    PollRepContent, PollReq, PollReqContent, PopoDecKeyRespContent, RevDetails, RevReqContent,
};
use tc_asn1_x509::name::GeneralName;

const CRMF_CERT_REQ_MSG: &[u8] = include_bytes!("data/crmf_cert_req_msg.der");
const PROTECTED_PKI_MESSAGE: &[u8] = include_bytes!("data/protected_pki_message.der");

fn der<T: Decode>(bytes: &[u8]) -> T {
    let (len, value) = T::decode_der(bytes, &DecodingOptions::default()).unwrap();
    assert_eq!(len, bytes.len());
    value
}

fn round_trip<T: Decode + Encode + PartialEq + Debug>(value: &T) -> Vec<u8> {
    let encoding = value.encode_to_vec(&EncodingOptions::DER).unwrap();
    assert_eq!(&der::<T>(&encoding), value);
    encoding
}

fn name(dn: &str) -> GeneralName {
    GeneralName::DirectoryName(dn.parse().unwrap())
}

fn header() -> PkiHeader {
    PkiHeader::new(2.into(), name("CN=Sender"), name("CN=Recip"))
}

#[test]
fn bc_crmf_request_round_trips_byte_for_byte() {
    let message: CertReqMsg = der(CRMF_CERT_REQ_MSG);
    assert_eq!(
        message.encode_to_vec(&EncodingOptions::DER).unwrap(),
        CRMF_CERT_REQ_MSG
    );
    let template = message.cert_req().cert_template();
    assert!(template.subject().is_some());
    assert!(template.public_key().is_some());
    assert!(matches!(
        message.popo(),
        Some(ProofOfPossession::Signature(_))
    ));
}

#[test]
fn bc_java_protected_message_round_trips_and_names_its_pbm_parameters() {
    let message: PkiMessage = der(PROTECTED_PKI_MESSAGE);
    assert_eq!(
        message.encode_to_vec(&EncodingOptions::DER).unwrap(),
        PROTECTED_PKI_MESSAGE
    );
    let header = message.header();
    assert_eq!(header.pvno(), &Asn1Integer::from(2));
    let protection = header.protection_alg().unwrap();
    assert_eq!(*protection.algorithm(), CrmfId::PASSWORD_BASED_MAC.oid());
    let parameters = protection
        .parameters()
        .unwrap()
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap();
    let pbm: PbmParameter = der(&parameters);
    assert_eq!(pbm.iteration_count(), &Asn1Integer::from(1000));

    let PkiBody::Ip(response) = message.body() else {
        panic!("an initialization response expected");
    };
    assert!(response.response().is_empty());
    assert!(message.protection().is_some());
    assert_eq!(message.extra_certs().map(<[_]>::len), Some(1));
}

#[test]
fn a_confirmation_body_is_an_explicitly_tagged_null() {
    let message = PkiMessage::new(header(), PkiBody::Pkiconf);
    let encoding = round_trip(&message);
    assert!(encoding.ends_with(&[0xb3, 2, 5, 0]));
}

#[test]
fn bodies_round_trip_under_their_context_tags() {
    let rejection = PkiStatusInfo::new(PkiStatus::Rejection);
    let bodies = [
        (PkiBody::Ip(CertRepMessage::new(vec![])), 0xa1),
        (
            PkiBody::Genm(GenMsgContent::new(vec![
                InfoTypeAndValue::new(CmpId::IMPLICIT_CONFIRM.oid())
                    .with_info_value(Asn1Any::primitive(tag::NULL, &[])),
            ])),
            0xb5,
        ),
        (
            PkiBody::Error(ErrorMsgContent::new(rejection).with_error_code(7.into())),
            0xb7,
        ),
        (
            PkiBody::PollReq(PollReqContent::new(vec![PollReq::new(1.into())])),
            0xb9,
        ),
        (
            PkiBody::PollRep(PollRepContent::new(vec![PollRep::new(1.into(), 60.into())])),
            0xba,
        ),
        (
            PkiBody::Popdecr(PopoDecKeyRespContent::new(vec![42.into()])),
            0xa6,
        ),
        (
            PkiBody::Rr(RevReqContent::new(vec![RevDetails::new(
                CertTemplate::new().with_serial_number(5.into()),
            )])),
            0xab,
        ),
        (
            PkiBody::Cann(CmpCertificate::OtherCert(der(&[0xa1, 3, 2, 1, 9]))),
            0xb0,
        ),
    ];
    for (body, first) in bodies {
        assert_eq!(round_trip(&body)[0], first);
    }
}

#[test]
fn nested_messages_hold_whole_messages() {
    let inner = PkiMessage::new(header(), PkiBody::Pkiconf);
    let nested = PkiMessages::new(vec![inner.clone(), inner]).unwrap();
    let outer = PkiMessage::new(header(), PkiBody::Nested(nested));
    round_trip(&outer);
    assert_eq!(PkiMessages::new(vec![]), Err(Asn1Error::MalformedValue));
}

#[test]
fn other_certificates_need_a_context_tag() {
    let options = DecodingOptions::default();
    assert_eq!(
        CmpCertificate::decode_der(&[0x04, 1, 0], &options),
        Err(Asn1Error::UnexpectedTag)
    );
    let other = CmpCertificate::decode_der(&[0xa3, 2, 5, 0], &options)
        .unwrap()
        .1;
    assert_eq!(round_trip(&other), [0xa3, 2, 5, 0]);
}

#[test]
fn proofs_of_possession_mix_implicit_and_explicit_tags() {
    assert_eq!(round_trip(&ProofOfPossession::RaVerified), [0x80, 0]);
    let later = ProofOfPossession::KeyEncipherment(PopoPrivKey::SubsequentMessage(
        SubsequentMessage::EncrCert,
    ));
    assert_eq!(round_trip(&later), [0xa2, 3, 0x81, 1, 0]);
    assert_eq!(
        ProofOfPossession::decode_der(&[0x80, 1, 0], &DecodingOptions::default()),
        Err(Asn1Error::MalformedValue)
    );
}

#[test]
fn archive_options_tag_a_boolean_implicitly() {
    let options = PkiArchiveOptions::ArchiveRemGenPrivKey(Asn1Boolean::from(true));
    assert_eq!(round_trip(&options), [0x82, 1, 0xff]);
}

#[test]
fn a_request_with_a_proof_and_registration_info_round_trips() {
    let template = CertTemplate::new()
        .with_version(2.into())
        .with_subject("CN=Requester".parse().unwrap());
    let request = CertRequest::new(1.into(), template);
    let message = CertReqMsg::new(request)
        .with_popo(ProofOfPossession::RaVerified)
        .with_reg_info(vec![tc_asn1_cmp::crmf::AttributeTypeAndValue::new(
            CrmfId::UTF8_PAIRS.oid(),
            Asn1Any::primitive(tag::UTF8_STRING, b"k?v%"),
        )]);
    round_trip(&message);
    round_trip(&CertReqMessages::new(vec![message]).unwrap());
}

#[test]
fn controls_and_request_lists_need_at_least_one_entry() {
    let options = DecodingOptions::default();
    assert_eq!(Controls::new(vec![]), Err(Asn1Error::MalformedValue));
    assert_eq!(
        Controls::decode_der(&[0x30, 0], &options),
        Err(Asn1Error::MalformedValue)
    );
    assert_eq!(CertReqMessages::new(vec![]), Err(Asn1Error::MalformedValue));
}

#[test]
fn identifier_tables_sit_under_their_arcs() {
    assert_eq!(CmpId::IMPLICIT_CONFIRM.dotted(), "1.3.6.1.5.5.7.4.13");
    assert_eq!(CrmfId::REG_TOKEN.dotted(), "1.3.6.1.5.5.7.5.1.1");
    assert_eq!(
        CrmfId::from_oid(&CrmfId::PASSWORD_BASED_MAC.oid()),
        Some(CrmfId::PASSWORD_BASED_MAC)
    );
}
