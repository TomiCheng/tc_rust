use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};
use tc_asn1::{
    Asn1Any, Asn1BitString, Asn1OctetString, Asn1Utf8String, Decode, DecodingOptions, Encode,
    EncodingOptions,
};
use tc_asn1_cmp::{
    PkiBody,
    crmf::{
        AttributeTypeAndValue, AuthInfo, CertId, CertReqMsg, CertRequest, CertTemplate, CrmfId,
        PkMacValue, PkiArchiveOptions, PkiPublicationInfo, PopoSigningKey, ProofOfPossession,
        SinglePubInfo, SubsequentMessage,
    },
};
use tc_asn1_x509::{alg::AlgorithmIdentifier, name::GeneralName};
use tc_crmf::{
    CertificateReqMessages, CertificateReqMessagesBuilder, CertificateRequestMessage,
    CertificateRequestMessageBuilder, Control, CrmfError, PkMacBuilder,
    ProofOfPossessionSigningKeyBuilder, ProofOfPossessionType, SubsequentMessageType,
};
use tc_x509::{
    DefaultX509OperatorBuilder, X509Operator, X509OperatorBuilder,
    operator::{signer::SignatureFactory, verifier::VerifierFactoryProvider},
};

fn identity(
    x509: &dyn X509Operator,
) -> (
    tc_asn1_x509::cert::SubjectPublicKeyInfo,
    Box<dyn SignatureFactory>,
    Box<dyn VerifierFactoryProvider>,
) {
    let mut generator = x509.key_pair_generator().get_by_name("Ed25519").unwrap();
    let (public, private) = generator.generate().unwrap().into_parts();
    let spki = x509.spki().encode(&*public).unwrap();
    let signer = x509.signature_factory("Ed25519", private.into()).unwrap();
    (spki, signer, x509.verifier_factory_provider(public.into()))
}

fn round_trip(message: &CertificateRequestMessage) -> CertificateRequestMessage {
    let encoded = message.encode().unwrap();
    let decoded = CertificateRequestMessage::decode(&encoded).unwrap();
    assert_eq!(&decoded, message);
    decoded
}

#[test]
fn a_basic_message_retains_the_subject_and_key_and_verifies_its_signature() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (key, signer, verifier) = identity(&*x509);
    let subject = "CN=Test".parse().unwrap();
    let mut builder = CertificateRequestMessageBuilder::new(1.into());
    let params = x509.spki().decode(&key).unwrap();
    builder
        .set_subject(subject)
        .set_public_key(&*x509, &*params)
        .unwrap()
        .set_proof_of_possession_signing_key_signer(&*signer)
        .unwrap();
    let message = round_trip(&builder.build().unwrap());
    assert_eq!(message.cert_req_id(), &1.into());
    assert_eq!(
        message.cert_template().subject().unwrap().to_string(),
        "CN=Test"
    );
    assert_eq!(message.cert_template().public_key(), Some(&key));
    assert!(message.is_valid_signing_key_pop(&*verifier).unwrap());
}

#[test]
fn an_old_certificate_control_round_trips_the_issuer_and_serial() {
    let expected = CertId::new(
        GeneralName::DirectoryName("CN=Old Cert".parse().unwrap()),
        42.into(),
    );
    let mut builder = CertificateRequestMessageBuilder::new(1.into());
    builder
        .add_control(Control::OldCertId(expected.clone()))
        .unwrap();
    let message = round_trip(&builder.build().unwrap());
    assert_eq!(
        message.control(&CrmfId::OLD_CERT_ID.oid()).unwrap(),
        Some(Control::OldCertId(expected))
    );
}

#[test]
fn a_protocol_encryption_key_control_round_trips_its_public_key() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (key, _, _) = identity(&*x509);
    let mut builder = CertificateRequestMessageBuilder::new(1.into());
    builder
        .add_control(Control::ProtocolEncrKey(key.clone()))
        .unwrap();
    let message = round_trip(&builder.build().unwrap());
    assert_eq!(
        message.control(&CrmfId::PROTOCOL_ENCR_KEY.oid()).unwrap(),
        Some(Control::ProtocolEncrKey(key))
    );
}

#[test]
fn publication_control_preserves_explicit_locations_no_publication_and_no_preference() {
    let publication = SinglePubInfo::new(1.into())
        .with_pub_location(GeneralName::DirectoryName("CN=Test CA".parse().unwrap()));
    for expected in [
        PkiPublicationInfo::new(1.into()).with_pub_infos(vec![publication]),
        PkiPublicationInfo::new(0.into()),
        PkiPublicationInfo::new(1.into()),
    ] {
        let mut builder = CertificateRequestMessageBuilder::new(1.into());
        builder
            .add_control(Control::PkiPublicationInfo(expected.clone()))
            .unwrap();
        let message = round_trip(&builder.build().unwrap());
        assert_eq!(
            message
                .control(&CrmfId::PKI_PUBLICATION_INFO.oid())
                .unwrap(),
            Some(Control::PkiPublicationInfo(expected))
        );
    }
}

#[test]
fn registration_information_survives_encoding_alongside_a_valid_signing_proof() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (key, signer, verifier) = identity(&*x509);
    let pair = raw_text_attribute(CrmfId::UTF8_PAIRS.oid(), "CertType?Server%");
    let mut builder = CertificateRequestMessageBuilder::new(1.into());
    builder
        .set_subject("CN=Test".parse().unwrap())
        .set_subject_public_key_info(key)
        .set_reg_info(vec![pair.clone()])
        .set_proof_of_possession_signing_key_signer(&*signer)
        .unwrap();
    let message = round_trip(&builder.build().unwrap());
    assert_eq!(message.reg_info(), Some([pair].as_slice()));
    assert!(message.is_valid_signing_key_pop(&*verifier).unwrap());
}

fn raw_text_attribute(oid: tc_asn1::Asn1Oid, text: &str) -> AttributeTypeAndValue {
    let bytes = Asn1Utf8String::new(text)
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap();
    let (_, value) = Asn1Any::decode_der(&bytes, &DecodingOptions::default()).unwrap();
    AttributeTypeAndValue::new(oid, value)
}

#[test]
fn raw_control_lookup_preserves_known_and_unknown_values_and_detects_absence() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (key, _, _) = identity(&*x509);
    let unknown = raw_text_attribute(
        "1.3.6.1.4.1.32473.1".parse().unwrap(),
        "unrecognized control",
    );
    let known = Control::ProtocolEncrKey(key);
    let mut builder = CertificateRequestMessageBuilder::new(1.into());
    builder
        .add_control(known.clone())
        .unwrap()
        .add_raw_control(unknown.clone());
    let message = round_trip(&builder.build().unwrap());
    assert!(message.has_controls());
    assert_eq!(
        message.control_value(&known.oid()),
        Some(known.to_asn1().unwrap().value())
    );
    assert!(message.has_control(unknown.attribute_type()));
    assert_eq!(message.control(unknown.attribute_type()).unwrap(), None);
    assert_eq!(
        message.control_value(unknown.attribute_type()),
        Some(unknown.value())
    );
    assert!(!message.has_control(&CrmfId::OLD_CERT_ID.oid()));
    assert!(message.control_value(&CrmfId::OLD_CERT_ID.oid()).is_none());
}

#[test]
fn a_sender_authenticates_the_public_key_input_and_the_password_path_fails() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (key, signer, verifier) = identity(&*x509);
    let algo = DefaultAlgoBuilder::default().build();
    let pk_mac = PkMacBuilder::new(algo.digest(), algo.mac());
    let mut builder = CertificateRequestMessageBuilder::new(1.into());
    builder
        .set_subject_public_key_info(key.clone())
        .set_auth_info_sender_name("CN=Test".parse().unwrap())
        .set_proof_of_possession_signing_key_signer(&*signer)
        .unwrap();
    let message = round_trip(&builder.build().unwrap());
    let Some(ProofOfPossession::Signature(pop)) = message.to_asn1().popo() else {
        panic!("missing signing POP")
    };
    let input = pop.poposk_input().unwrap();
    assert_eq!(input.public_key(), &key);
    assert!(matches!(input.auth_info(), AuthInfo::Sender(_)));
    assert!(message.is_valid_signing_key_pop(&*verifier).unwrap());
    assert!(
        message
            .is_valid_signing_key_pop_with_mac(&*verifier, &pk_mac, "fred")
            .is_err()
    );

    let (other_key, _, _) = identity(&*x509);
    let changed_request =
        CertRequest::new(1.into(), CertTemplate::new().with_public_key(other_key));
    let changed = CertificateRequestMessage::from(
        CertReqMsg::new(changed_request).with_popo(ProofOfPossession::Signature(pop.clone())),
    );
    assert!(!changed.is_valid_signing_key_pop(&*verifier).unwrap());
}

#[test]
fn password_authenticated_proof_verifies_with_the_right_password_only() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (key, signer, verifier) = identity(&*x509);
    let algo = DefaultAlgoBuilder::default().build();
    let pk_mac = PkMacBuilder::new(algo.digest(), algo.mac());
    let mut builder = CertificateRequestMessageBuilder::new(1.into());
    builder
        .set_subject_public_key_info(key.clone())
        .set_auth_info_pk_mac_builder(&pk_mac, "密碼")
        .set_proof_of_possession_signing_key_signer(&*signer)
        .unwrap();
    let message = round_trip(&builder.build().unwrap());
    assert_eq!(message.cert_template().public_key(), Some(&key));
    assert!(message.has_signing_key_pop_with_pk_mac());
    assert!(message.is_valid_signing_key_pop(&*verifier).is_err());
    assert!(
        message
            .is_valid_signing_key_pop_with_mac(&*verifier, &pk_mac, "密碼")
            .unwrap()
    );
    assert!(
        !message
            .is_valid_signing_key_pop_with_mac(&*verifier, &pk_mac, "wrong")
            .unwrap()
    );
}

#[test]
fn the_mac_predicate_is_false_when_proof_or_signing_key_input_is_absent() {
    let request = CertRequest::new(1.into(), CertTemplate::new());
    let absent = CertificateRequestMessage::from(CertReqMsg::new(request.clone()));
    assert!(!absent.has_signing_key_pop_with_pk_mac());
    let algorithm = AlgorithmIdentifier::new("1.2.840.113549.1.1.11".parse().unwrap());
    let pop = PopoSigningKey::new(algorithm, Asn1BitString::from_bytes(&[1, 2, 3, 4]));
    let direct = CertificateRequestMessage::from(
        CertReqMsg::new(request).with_popo(ProofOfPossession::Signature(pop)),
    );
    assert!(!direct.has_signing_key_pop_with_pk_mac());
}

#[test]
fn a_complete_template_signs_the_certificate_request_even_when_a_sender_is_set() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (key, signer, verifier) = identity(&*x509);
    let mut builder = CertificateRequestMessageBuilder::new(1.into());
    builder
        .set_subject_public_key_info(key)
        .set_subject("CN=Test".parse().unwrap())
        .set_auth_info_sender_name("CN=Test".parse().unwrap())
        .set_proof_of_possession_signing_key_signer(&*signer)
        .unwrap();
    let message = round_trip(&builder.build().unwrap());
    let Some(ProofOfPossession::Signature(pop)) = message.to_asn1().popo() else {
        panic!("missing signing POP")
    };
    assert!(pop.poposk_input().is_none());
    assert!(message.is_valid_signing_key_pop(&*verifier).unwrap());
}

#[test]
fn incomplete_signing_proofs_are_rejected_before_a_message_is_built() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (key, signer, _) = identity(&*x509);
    let algo = DefaultAlgoBuilder::default().build();
    let pk_mac = PkMacBuilder::new(algo.digest(), algo.mac());
    let mut plain = CertificateRequestMessageBuilder::new(1.into());
    let mut sender = CertificateRequestMessageBuilder::new(1.into());
    sender
        .set_subject("CN=Test".parse().unwrap())
        .set_auth_info_sender_name("CN=Test".parse().unwrap());
    let mut mac = CertificateRequestMessageBuilder::new(1.into());
    mac.set_auth_info_pk_mac_builder(&pk_mac, "fred");
    for builder in [&mut plain, &mut sender, &mut mac] {
        builder
            .set_proof_of_possession_signing_key_signer(&*signer)
            .unwrap();
        assert!(
            matches!(builder.build(), Err(CrmfError::Invalid(message)) if message.contains("requires a public key"))
        );
    }
    plain.set_subject_public_key_info(key.clone());
    assert!(
        matches!(plain.build(), Err(CrmfError::Invalid(message)) if message.contains("requires a sender or PKMAC"))
    );

    let mut signing = ProofOfPossessionSigningKeyBuilder::from_public_key(&key);
    assert!(signing.build(&*signer).is_err());
    signing.set_sender(GeneralName::DirectoryName("CN=Test".parse().unwrap()));
    signing.set_public_key_mac(&pk_mac, "fred").unwrap();
    assert!(signing.build(&*signer).is_err());
}

#[test]
fn every_proof_choice_rejects_a_second_proof_and_the_default_is_ra_verified() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (_, signer, _) = identity(&*x509);
    let mac = PkMacValue::new(
        AlgorithmIdentifier::new(CrmfId::PASSWORD_BASED_MAC.oid()),
        Asn1BitString::from_bytes(&[1]),
    );
    let mut builder = CertificateRequestMessageBuilder::new(1.into());
    assert_eq!(
        builder.build().unwrap().proof_of_possession_type(),
        Some(ProofOfPossessionType::RaVerified)
    );
    builder
        .set_proof_of_possession_agree_mac(mac.clone())
        .unwrap();
    assert!(builder.set_proof_of_possession_ra_verified().is_err());
    assert!(builder.set_proof_of_possession_agree_mac(mac).is_err());
    assert!(
        builder
            .set_proof_of_possession_signing_key_signer(&*signer)
            .is_err()
    );
    assert!(
        builder
            .set_proof_of_possession_subsequent_message(SubsequentMessage::EncrCert)
            .is_err()
    );
    assert!(
        builder
            .set_proof_of_possession_subsequent_message_with_type(
                SubsequentMessageType::KeyAgreement,
                SubsequentMessage::ChallengeResp
            )
            .is_err()
    );
    assert_eq!(
        round_trip(&builder.build().unwrap()).proof_of_possession_type(),
        Some(ProofOfPossessionType::KeyAgreement)
    );
}

#[test]
fn request_lists_round_trip_in_every_cmp_request_body_and_clear_the_builder() {
    let request = CertificateRequestMessageBuilder::new(1.into())
        .build()
        .unwrap();
    let mut builder = CertificateReqMessagesBuilder::new();
    builder.add_request(&request);
    let list = builder.build().unwrap();
    for body in [
        PkiBody::Ir(list.to_asn1().clone()),
        PkiBody::Cr(list.to_asn1().clone()),
        PkiBody::Kur(list.to_asn1().clone()),
        PkiBody::Krr(list.to_asn1().clone()),
        PkiBody::Ccr(list.to_asn1().clone()),
    ] {
        assert!(CertificateReqMessages::is_certificate_request_messages(
            &body
        ));
        assert_eq!(
            CertificateReqMessages::from_pki_body(&body)
                .unwrap()
                .requests()
                .as_slice(),
            std::slice::from_ref(&request)
        );
    }
    assert!(!CertificateReqMessages::is_certificate_request_messages(
        &PkiBody::Pkiconf
    ));
    assert!(CertificateReqMessages::from_pki_body(&PkiBody::Pkiconf).is_err());
    assert!(builder.build().is_err());
}

#[test]
fn registration_tokens_authenticators_and_raw_archive_options_round_trip() {
    let controls = [
        Control::RegToken(Asn1Utf8String::new("token")),
        Control::Authenticator(Asn1Utf8String::new("authenticator")),
        Control::PkiArchive(Box::new(PkiArchiveOptions::KeyGenParameters(
            Asn1OctetString::new(&[1, 2, 3]),
        ))),
    ];
    let mut builder = CertificateRequestMessageBuilder::new(1.into());
    for control in &controls {
        builder.add_control(control.clone()).unwrap();
    }
    let message = round_trip(&builder.build().unwrap());
    for control in controls {
        assert_eq!(message.control(&control.oid()).unwrap(), Some(control));
    }
}
