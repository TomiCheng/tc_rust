#![cfg(feature = "rsa")]

use tc_openpgp::{DefaultPgpOperatorBuilder, PgpOperatorBuilder};
use tc_openpgp_packet::{
    ArmorKind, AsciiArmor, DecodingConfig, EncodingConfig, PacketHeaderFormat, PgpRead, PgpWrite,
    SignaturePacket, SignatureTypeId, SignatureVersion,
};

// Generated with GnuPG 2.4.9 from a disposable RSA-2048 key.
// Binary: --digest-algo SHA256 --detach-sign.
// Text: --digest-algo SHA512 --textmode --detach-sign.
const PUBLIC_KEY: &str = include_str!("fixtures/rsa_v4_public.asc");
const BINARY_SIGNATURE: &str = include_str!("fixtures/rsa_v4_binary.asc");
const TEXT_SIGNATURE: &str = include_str!("fixtures/rsa_v4_text.asc");

fn decode(armor: &str) -> (SignaturePacket, Vec<u8>) {
    let bytes = AsciiArmor::decode(ArmorKind::Signature, armor).unwrap();
    let mut input = bytes.as_slice();
    let packet = SignaturePacket::decode(&mut input, &DecodingConfig::default()).unwrap();
    assert!(input.is_empty());
    (packet, bytes)
}

#[test]
fn verifies_gnupg_v4_rsa_binary_signature_and_rejects_tampering() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let public_bytes = AsciiArmor::decode(ArmorKind::PublicKey, PUBLIC_KEY).unwrap();
    let public = operator.serializer().decode(&public_bytes).unwrap();
    let provider = operator.detached_signature();
    let (signature, bytes) = decode(BINARY_SIGNATURE);
    assert_eq!(signature.version(), SignatureVersion::V4);
    assert_eq!(signature.signature_type(), SignatureTypeId::BINARY_DOCUMENT);
    assert!(signature.salt().is_empty());

    let mut recoded = Vec::new();
    let config = EncodingConfig {
        header_format: PacketHeaderFormat::Legacy,
    };
    assert_eq!(
        signature.encode(&mut recoded, &config).unwrap() as usize,
        bytes.len()
    );
    assert_eq!(recoded, bytes);

    let document = [1, 0, 255, 13, 10, 2, 10, 128];
    assert!(
        provider
            .verify(&public, &mut document.as_slice(), &signature)
            .unwrap()
    );
    let mut modified = document;
    modified[0] ^= 1;
    assert!(
        !provider
            .verify(&public, &mut modified.as_slice(), &signature)
            .unwrap()
    );

    let mut changed = signature.signature().to_vec();
    *changed.last_mut().unwrap() ^= 1;
    let bad = signature
        .clone()
        .with_signature(signature.hash_prefix(), changed);
    assert!(
        !provider
            .verify(&public, &mut document.as_slice(), &bad)
            .unwrap()
    );

    let mut invalid_mpi = signature.signature().to_vec();
    invalid_mpi.push(0);
    let malformed = signature
        .clone()
        .with_signature(signature.hash_prefix(), invalid_mpi);
    assert!(
        provider
            .verify(&public, &mut document.as_slice(), &malformed)
            .is_err()
    );
    let mut subpackets = signature.hashed_subpackets().to_vec();
    subpackets.extend_from_slice(&[1, 0xff]);
    let unsupported = signature.with_subpackets(subpackets, Vec::new());
    assert!(matches!(
        provider.verify(&public, &mut document.as_slice(), &unsupported),
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported
    ));
}

#[test]
fn verifies_gnupg_v4_rsa_canonical_text_signature() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let public_bytes = AsciiArmor::decode(ArmorKind::PublicKey, PUBLIC_KEY).unwrap();
    let public = operator.serializer().decode(&public_bytes).unwrap();
    let (signature, _) = decode(TEXT_SIGNATURE);
    assert_eq!(
        signature.signature_type(),
        SignatureTypeId::CANONICAL_TEXT_DOCUMENT
    );
    let provider = operator.detached_signature();
    for mut text in [
        &b"first line\nsecond line\n"[..],
        &b"first line\r\nsecond line\r\n"[..],
    ] {
        assert!(provider.verify(&public, &mut text, &signature).unwrap());
    }
}
