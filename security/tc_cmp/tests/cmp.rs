use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};
use tc_asn1::{Asn1BitString, Asn1OctetString};
use tc_asn1_cmp::{CmpCertificate, PkiBody, PkiHeader, PkiMessage, RevReqContent};
use tc_asn1_x509::{alg::AlgorithmIdentifier, name::GeneralName};
use tc_cmp::{
    CertificateConfirmationContent, CertificateConfirmationContentBuilder, CertificateRequestType,
    GeneralPkiMessage, ProtectedPkiMessage, ProtectedPkiMessageBuilder, RevocationDetails,
    RevocationDetailsBuilder,
};
use tc_crmf::{
    CertificateReqMessages, CertificateReqMessagesBuilder, CertificateRequestMessageBuilder,
    PkMacBuilder,
};
use tc_x509::{DefaultX509OperatorBuilder, X509OperatorBuilder, cert::X509V3CertificateGenerator};

fn name(name: &str) -> GeneralName {
    GeneralName::DirectoryName(name.parse().unwrap())
}

fn builder() -> ProtectedPkiMessageBuilder {
    ProtectedPkiMessageBuilder::new(name("CN=Sender"), name("CN=Recipient"))
}

#[test]
fn a_signed_cmp_request_verifies_both_message_protection_and_crmf_proof() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let mut key_gen = x509.key_pair_generator().get_by_name("Ed25519").unwrap();
    let (public, private) = key_gen.generate().unwrap().into_parts();
    let factory = x509.signature_factory("Ed25519", private.into()).unwrap();
    let mut request = CertificateRequestMessageBuilder::new(7.into());
    request
        .set_subject("CN=Sender".parse().unwrap())
        .set_public_key(&*x509, &*public)
        .unwrap()
        .set_proof_of_possession_signing_key_signer(&*factory)
        .unwrap();
    let mut requests = CertificateReqMessagesBuilder::new();
    requests.add_request(&request.build().unwrap());
    let requests = requests.build().unwrap();
    let provider = x509.verifier_factory_provider(public.into());

    let message = builder()
        .with_transaction_id(b"transaction")
        .with_sender_nonce(&[0x11; 16])
        .with_certificate_requests(CertificateRequestType::Initialization, &requests)
        .build(&*factory)
        .unwrap();
    let wire = message.encode().unwrap();
    let decoded = ProtectedPkiMessage::decode(&wire).unwrap();
    assert_eq!(decoded, message);
    assert_eq!(
        decoded.header().transaction_id().unwrap().as_bytes(),
        b"transaction"
    );
    assert_eq!(
        decoded.header().sender_nonce().unwrap().as_bytes(),
        &[0x11; 16]
    );
    assert!(decoded.verify_signature(&*provider).unwrap());
    let decoded_requests = CertificateReqMessages::from_pki_body(decoded.body()).unwrap();
    assert_eq!(decoded_requests, requests);
    assert!(
        decoded_requests.requests()[0]
            .is_valid_signing_key_pop(&*provider)
            .unwrap()
    );

    let protection = decoded.to_asn1().protection().unwrap().clone();
    let header_changed = decoded
        .header()
        .clone()
        .with_transaction_id(Asn1OctetString::new(b"changed"));
    for (header, body) in [
        (header_changed, decoded.body().clone()),
        (decoded.header().clone(), PkiBody::Pkiconf),
    ] {
        let tampered = PkiMessage::new(header, body).with_protection(protection.clone());
        assert!(
            !ProtectedPkiMessage::try_from(tampered)
                .unwrap()
                .verify_signature(&*provider)
                .unwrap()
        );
    }
}

#[test]
fn bc_java_password_mac_verifies_and_rejects_a_wrong_password() {
    // From ProtectedMessageTest.TestVerifyBCJavaGeneratedMessage in bc-csharp.
    let der = include_bytes!("data/bc_java_protected_message.der");
    let message = ProtectedPkiMessage::decode(der).unwrap();
    assert_eq!(message.encode().unwrap(), der);
    assert!(message.has_password_based_mac_protection());
    assert!(matches!(message.body(), PkiBody::Ip(_)));
    assert_eq!(message.extra_certificates().len(), 1);
    let algo = DefaultAlgoBuilder::default().build();
    let pbm = PkMacBuilder::new(algo.digest(), algo.mac());
    assert!(message.verify_password_based_mac(&pbm, "secret").unwrap());
    assert!(!message.verify_password_based_mac(&pbm, "wrong").unwrap());
}

#[test]
fn a_built_password_mac_protects_the_header_and_body_when_encoded() {
    let algo = DefaultAlgoBuilder::default().build();
    let pbm = PkMacBuilder::new(algo.digest(), algo.mac())
        .with_iteration_count(100)
        .unwrap();
    let protection = pbm.build("密碼").unwrap();
    let message = builder()
        .with_recip_nonce(&[0x22; 16])
        .with_body(PkiBody::Pkiconf)
        .build_with_mac(&protection)
        .unwrap();
    assert_eq!(message.protection_algorithm(), protection.algorithm());
    let encoded = message.encode().unwrap();
    let decoded = ProtectedPkiMessage::decode(&encoded).unwrap();
    assert!(decoded.verify_password_based_mac(&pbm, "密碼").unwrap());
    assert!(!decoded.verify_password_based_mac(&pbm, "wrong").unwrap());

    let changed = PkiMessage::new(
        decoded
            .header()
            .clone()
            .with_recip_nonce(Asn1OctetString::new(&[0x44; 16])),
        PkiBody::Pkiconf,
    )
    .with_protection(decoded.to_asn1().protection().unwrap().clone());
    assert!(
        !ProtectedPkiMessage::try_from(changed)
            .unwrap()
            .verify_password_based_mac(&pbm, "密碼")
            .unwrap()
    );

    let error = builder().build_with_mac(&protection).unwrap_err();
    assert_eq!(error.to_string(), "missing CMP message body");
}

#[test]
fn general_messages_require_complete_der_and_protected_messages_require_both_fields() {
    let header = PkiHeader::new(2.into(), name("CN=Sender"), name("CN=Recipient"));
    let unprotected = GeneralPkiMessage::from(PkiMessage::new(header.clone(), PkiBody::Pkiconf));
    let mut encoded = unprotected.encode().unwrap();
    assert!(
        !GeneralPkiMessage::decode(&encoded)
            .unwrap()
            .has_protection()
    );
    assert!(ProtectedPkiMessage::decode(&encoded).is_err());
    encoded.push(0);
    assert!(GeneralPkiMessage::decode(&encoded).is_err());

    let missing_algorithm = PkiMessage::new(header.clone(), PkiBody::Pkiconf)
        .with_protection(Asn1BitString::from_bytes(&[1]));
    assert!(ProtectedPkiMessage::try_from(missing_algorithm).is_err());
    let missing_bits = PkiMessage::new(
        header.with_protection_alg(AlgorithmIdentifier::new("1.3.101.112".parse().unwrap())),
        PkiBody::Pkiconf,
    );
    assert!(ProtectedPkiMessage::try_from(missing_bits).is_err());
}

#[test]
fn certificate_confirmation_checks_the_hash_and_preserves_the_request_identifier() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let mut key_gen = x509.key_pair_generator().get_by_name("Ed25519").unwrap();
    let (public, private) = key_gen.generate().unwrap().into_parts();
    let factory = x509.signature_factory("Ed25519", private.into()).unwrap();
    let mut certificate = X509V3CertificateGenerator::new();
    certificate.set_subject_by_str("CN=Sender").unwrap();
    certificate.set_issuer_by_str("CN=Sender").unwrap();
    certificate.set_subject_public_key_info(x509.spki().encode(&*public).unwrap());
    certificate.set_validity_days(1).unwrap();
    certificate.set_serial_number(1.into()).unwrap();
    let issued = certificate.generate(&*factory).unwrap();
    let mut rsa = x509.key_pair_generator().get_by_name("RSA").unwrap();
    rsa.init(&tc_x509::operator::params::generate::RsaKeyGenParams::new(
        1024,
    ))
    .unwrap();
    let (_, rsa_private) = rsa.generate().unwrap().into_parts();
    let rsa_factory = x509
        .signature_factory("SHA-256withRSA", rsa_private.into())
        .unwrap();
    certificate.set_issuer_by_str("CN=Issuing CA").unwrap();
    certificate.set_serial_number(2.into()).unwrap();
    let other = CmpCertificate::X509v3PkCert(
        certificate
            .generate(&*rsa_factory)
            .unwrap()
            .certificate()
            .clone(),
    );
    let cert = CmpCertificate::X509v3PkCert(issued.certificate().clone());
    let algo = DefaultAlgoBuilder::default().build();
    let sha512 = AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.3".parse().unwrap());
    let sha256 = AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse().unwrap());

    let mut confirmation = CertificateConfirmationContentBuilder::new(algo.digest());
    confirmation
        .add_accepted_certificate(&cert, 7.into(), sha512)
        .unwrap();
    confirmation
        .add_accepted_certificate_with_implicit_digest(&other, 8.into(), &sha256)
        .unwrap();
    let confirmation = confirmation.build();
    assert!(
        builder()
            .with_certificate_confirmation(&confirmation)
            .build(&*factory)
            .is_err()
    );

    let message =
        ProtectedPkiMessageBuilder::with_version(3.into(), name("CN=Sender"), name("CN=Recipient"))
            .with_certificate_confirmation(&confirmation)
            .add_certificate(&issued)
            .unwrap()
            .build(&*factory)
            .unwrap();
    let decoded = ProtectedPkiMessage::decode(&message.encode().unwrap()).unwrap();
    let confirmation = CertificateConfirmationContent::from_pki_body(decoded.body()).unwrap();
    assert_eq!(decoded.extra_certificates(), std::slice::from_ref(&cert));
    let mut statuses = confirmation.status_messages();
    let explicit = statuses.next().unwrap();
    assert_eq!(explicit.cert_req_id(), &7.into());
    assert!(explicit.is_verified(&cert, algo.digest(), None).unwrap());
    assert!(!explicit.is_verified(&other, algo.digest(), None).unwrap());
    let implicit = statuses.next().unwrap();
    assert_eq!(implicit.cert_req_id(), &8.into());
    assert!(implicit.is_verified(&other, algo.digest(), None).is_err());
    assert!(
        implicit
            .is_verified(&other, algo.digest(), Some(&sha256))
            .unwrap()
    );
}

#[test]
fn revocation_details_survive_the_round_trip_inside_a_cmp_request() {
    let issuer = "CN=CA".parse().unwrap();
    let mut details = RevocationDetailsBuilder::new();
    details.set_issuer(issuer).set_serial_number(42.into());
    let request = PkiMessage::new(
        PkiHeader::new(2.into(), name("CN=Sender"), name("CN=Recipient")),
        PkiBody::Rr(RevReqContent::new(vec![details.build().into_asn1()])),
    );
    let message =
        GeneralPkiMessage::decode(&GeneralPkiMessage::from(request).encode().unwrap()).unwrap();
    let PkiBody::Rr(content) = message.body() else {
        panic!("expected revocation request")
    };
    let details = RevocationDetails::from(content.details()[0].clone());
    assert_eq!(details.issuer().unwrap().to_string(), "CN=CA");
    assert_eq!(details.serial_number(), Some(&42.into()));
    assert!(details.subject().is_none());
}
