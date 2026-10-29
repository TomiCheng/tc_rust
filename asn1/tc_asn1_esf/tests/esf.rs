use std::fmt::Debug;

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1GeneralizedTime, Asn1OctetString, Asn1Oid, Asn1UtcTime, Asn1Utf8String,
    Decode, DecodingOptions, Encode, EncodingOptions, tag,
};
use tc_asn1_esf::{
    CertificateValues, CommitmentTypeIdentifier, CommitmentTypeIndication, CommitmentTypeQualifier,
    CompleteCertificateRefs, CompleteRevocationRefs, CrlIdentifier, CrlListId, CrlOcspRef,
    CrlValidatedId, EsfAttribute, OcspIdentifier, OcspListId, OcspResponsesId, OtherCertId,
    OtherHash, OtherHashAlgAndValue, OtherRevVals, OtherSigningCertificate, RevocationValues,
    SigPolicyQualifierInfo, SignaturePolicyId, SignaturePolicyIdentifier, SignerAttribute,
    SignerAttributeEntry, SignerLocation,
};
use tc_asn1_ocsp::ResponderId;
use tc_asn1_x500::{Attribute, AttributeValue, DirectoryString};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::crl::CertificateList;

/// An empty v1 CRL with an Ed25519 signature algorithm.
const CRL: &[u8] = &[
    0x30, 0x25, 0x30, 0x18, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 0x30, 0, 0x17, 13, b'2', b'6', b'0',
    b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z', 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 3,
    2, 0, 0xaa,
];

fn round_trip<T: Decode + Encode + PartialEq + Debug>(value: &T) -> Vec<u8> {
    let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
    let (len, back) = T::decode_der(&der, &DecodingOptions::default()).unwrap();
    assert_eq!(len, der.len());
    assert_eq!(&back, value);
    der
}

fn der<T: Decode>(bytes: &[u8]) -> T {
    T::decode_der(bytes, &DecodingOptions::default()).unwrap().1
}

fn text(s: &str) -> DirectoryString {
    DirectoryString::Utf8String(Asn1Utf8String::new(s))
}

fn sha1_hash() -> OtherHash {
    OtherHash::Sha1Hash(Asn1OctetString::new(&[0x11; 20]))
}

fn sha256_hash() -> OtherHashAlgAndValue {
    OtherHashAlgAndValue::new(
        AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse().unwrap()),
        Asn1OctetString::new(&[0x22; 32]),
    )
}

#[test]
fn bc_signer_location_round_trips_every_combination_of_fields() {
    let country = text("Australia");
    let locality = text("Melbourne");
    let lines = vec![text("line 1"), text("line 2")];
    for location in [
        SignerLocation::new().with_country_name(country.clone()),
        SignerLocation::new().with_locality_name(locality.clone()),
        SignerLocation::new()
            .with_country_name(country.clone())
            .with_locality_name(locality),
        SignerLocation::new()
            .with_country_name(country)
            .with_postal_address(lines)
            .unwrap(),
    ] {
        round_trip(&location);
    }
}

#[test]
fn bc_signer_location_rejects_seven_postal_lines_and_unknown_tags() {
    let seven: Vec<_> = (1..=7).map(|n| text(&format!("line {n}"))).collect();
    assert_eq!(
        SignerLocation::new().with_postal_address(seven.clone()),
        Err(Asn1Error::MalformedValue)
    );
    assert_eq!(
        SignerLocation::new().with_postal_address(vec![]),
        Err(Asn1Error::MalformedValue)
    );

    let six = SignerLocation::new()
        .with_postal_address(seven[..6].to_vec())
        .unwrap();
    let mut encoding = six.encode_to_vec(&EncodingOptions::DER).unwrap();
    let options = DecodingOptions::default();
    let line = text("line 7").encode_to_vec(&EncodingOptions::DER).unwrap();
    encoding.extend(&line);
    encoding[1] += line.len() as u8;
    encoding[3] += line.len() as u8;
    encoding[5] += line.len() as u8;
    assert_eq!(
        SignerLocation::decode_der(&encoding, &options),
        Err(Asn1Error::MalformedValue)
    );

    let mut tagged = round_trip(&SignerLocation::new().with_country_name(text("AU")));
    tagged[2] = 0xa5;
    assert!(SignerLocation::decode_der(&tagged, &options).is_err());
}

#[test]
fn bc_commitment_type_indication_round_trips_with_qualifiers() {
    let indication = CommitmentTypeIndication::new(CommitmentTypeIdentifier::PROOF_OF_ORIGIN.oid());
    round_trip(&indication);
    let qualifier = CommitmentTypeQualifier::new(CommitmentTypeIdentifier::PROOF_OF_ORIGIN.oid())
        .with_qualifier(Asn1Any::primitive(tag::UTF8_STRING, b"Text"));
    round_trip(&qualifier);
    let indication = indication.with_commitment_type_qualifier(vec![qualifier]);
    round_trip(&indication);
}

#[test]
fn other_hashes_are_a_bare_sha1_octet_string_or_a_sequence() {
    assert_eq!(round_trip(&sha1_hash())[0], 0x04);
    assert_eq!(round_trip(&OtherHash::from(sha256_hash()))[0], 0x30);
    assert_eq!(
        OtherHash::decode_der(&[0x02, 1, 0], &DecodingOptions::default()),
        Err(Asn1Error::UnexpectedTag)
    );
}

#[test]
fn bc_other_signing_certificate_round_trips() {
    let ids = vec![
        OtherCertId::new(sha1_hash()),
        OtherCertId::new(OtherHash::from(sha256_hash())),
    ];
    let certificate = OtherSigningCertificate::new(ids.clone());
    round_trip(&certificate);
    round_trip(&CompleteCertificateRefs::new(ids));
}

#[test]
fn signature_policies_are_explicit_or_implied() {
    let qualifier = SigPolicyQualifierInfo::new(
        "1.2.840.113549.1.9.16.5.1".parse().unwrap(),
        Asn1Any::primitive(tag::IA5_STRING, b"https://example.com/policy"),
    );
    let id = SignaturePolicyId::new("1.2.3.4".parse().unwrap(), sha256_hash())
        .with_sig_policy_qualifiers(vec![qualifier]);
    let explicit = SignaturePolicyIdentifier::from(id);
    assert_eq!(round_trip(&explicit)[0], 0x30);
    assert_eq!(
        round_trip(&SignaturePolicyIdentifier::SignaturePolicyImplied),
        [5, 0]
    );
}

#[test]
fn every_signer_attribute_entry_is_read_not_only_the_first() {
    let role = Attribute::new(
        "2.5.4.72".parse::<Asn1Oid>().unwrap(),
        vec![AttributeValue::DirectoryString(text("signer"))],
    )
    .unwrap();
    let attribute = SignerAttribute::new(vec![
        SignerAttributeEntry::claimed(vec![role.clone()]),
        SignerAttributeEntry::claimed(vec![role]),
    ]);
    let der = round_trip(&attribute);
    assert_eq!(der[2], 0xa0);
    assert_eq!(attribute.entries().len(), 2);
}

#[test]
fn revocation_references_and_values_round_trip() {
    let crl_id = CrlIdentifier::new(
        "CN=CA".parse().unwrap(),
        Asn1UtcTime::decode_der(b"\x17\x0d260101000000Z", &DecodingOptions::default())
            .unwrap()
            .1,
    )
    .with_crl_number(5.into());
    let crls = CrlListId::new(vec![
        CrlValidatedId::new(sha1_hash()).with_crl_identifier(crl_id),
    ]);
    let produced_at =
        Asn1GeneralizedTime::decode_der(b"\x18\x0f20260101000000Z", &DecodingOptions::default())
            .unwrap()
            .1;
    let ocsp = OcspListId::new(vec![
        OcspResponsesId::new(OcspIdentifier::new(
            ResponderId::ByKey(Asn1OctetString::new(&[3; 20])),
            produced_at,
        ))
        .with_ocsp_rep_hash(sha1_hash()),
    ]);
    let reference = CrlOcspRef::new().with_crlids(crls).with_ocspids(ocsp);
    round_trip(&reference);
    round_trip(&CompleteRevocationRefs::new(vec![
        reference,
        CrlOcspRef::new(),
    ]));

    let values = RevocationValues::new()
        .with_crl_vals(vec![der::<CertificateList>(CRL)])
        .with_other_rev_vals(OtherRevVals::new(
            "1.2.3.5".parse().unwrap(),
            Asn1Any::primitive(tag::NULL, &[]),
        ));
    round_trip(&values);
    assert_eq!(round_trip(&RevocationValues::new()), [0x30, 0]);
    assert_eq!(round_trip(&CertificateValues::new(vec![])), [0x30, 0]);
}

#[test]
fn esf_attribute_identifiers_sit_under_id_aa() {
    assert_eq!(
        EsfAttribute::ARCHIVE_TIMESTAMP_V2.dotted(),
        "1.2.840.113549.1.9.16.2.48"
    );
    assert_eq!(
        EsfAttribute::from_oid(&EsfAttribute::SIGNER_LOCATION.oid()),
        Some(EsfAttribute::SIGNER_LOCATION)
    );
}
