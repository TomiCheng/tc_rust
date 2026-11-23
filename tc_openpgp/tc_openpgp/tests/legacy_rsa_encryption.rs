#![cfg(feature = "legacy-encryption")]

use tc_algo::params::key::{RsaKey, RsaKeyParams};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_openpgp::{DefaultPgpOperatorBuilder, PgpKeyPair, PgpOperatorBuilder, PgpPrivateKey};
use tc_openpgp_packet::{ArmorKind, AsciiArmor, DecodingConfig, PacketTag, PgpReader};
use tc_rsa::RsaPrivateCrtKeyOwned;

const PUBLIC: &str = include_str!("fixtures/rsa_v3_encryption_public.asc");
const DISPOSABLE_CRT: &str = include_str!("fixtures/rsa_v3_disposable_crt.txt");
const MESSAGES: [&str; 3] = [
    include_str!("fixtures/rsa_v3_aes128.asc"),
    include_str!("fixtures/rsa_v3_aes192.asc"),
    include_str!("fixtures/rsa_v3_aes256.asc"),
];
const EXPECTED: &[u8] = &[0, 42, 13, 10, 127, 128, 255];

fn test_pair(operator: &dyn tc_openpgp::PgpOperator) -> PgpKeyPair {
    let public = AsciiArmor::decode(ArmorKind::PublicKey, PUBLIC).unwrap();
    let public = operator.serializer().decode(&public).unwrap();
    let rsa = public.key().as_any().downcast_ref::<RsaKey>().unwrap();
    let mut numbers = DISPOSABLE_CRT
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let bytes: Vec<u8> = (0..line.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&line[index..index + 2], 16).unwrap())
                .collect();
            let Ok(number) = PaddedBigUint::from_be(&bytes);
            number
        });
    let crt = RsaPrivateCrtKeyOwned::new(
        rsa.modulus().clone(),
        rsa.exponent().clone(),
        numbers.next().unwrap(),
        numbers.next().unwrap(),
        numbers.next().unwrap(),
        numbers.next().unwrap(),
        numbers.next().unwrap(),
        numbers.next().unwrap(),
    );
    assert!(numbers.next().is_none());
    let private = PgpPrivateKey::new(public.algorithm(), Box::new(RsaKey::Crt(crt)));
    PgpKeyPair::new(public, private)
}

#[test]
fn decrypts_uncompressed_gnupg_rsa_messages_with_all_aes_key_sizes() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let recipient = test_pair(&*operator);
    for armor in MESSAGES {
        let mut bytes = AsciiArmor::decode(ArmorKind::Message, armor).unwrap();
        bytes.extend_from_slice(b"next");
        let mut input = bytes.as_slice();
        let literal = operator
            .encrypted_message()
            .decrypt(&recipient, &mut input, &DecodingConfig::default())
            .unwrap();
        assert_eq!(literal.filename(), b"document.bin");
        assert_eq!(literal.data(), EXPECTED);
        assert_eq!(input, b"next");
    }
}

#[test]
fn rsa_and_mdc_failures_reject_plaintext_with_the_same_error() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let recipient = test_pair(&*operator);
    let provider = operator.encrypted_message();
    let config = DecodingConfig::default();
    let bytes = AsciiArmor::decode(ArmorKind::Message, MESSAGES[2]).unwrap();
    let mut input = bytes.as_slice();
    {
        let mut reader = PgpReader::new(&mut input);
        let (header, mut body) = reader.read_body(&config).unwrap();
        assert_eq!(header.tag(), PacketTag::PublicKeyEncryptedSession);
        std::io::copy(&mut body, &mut std::io::sink()).unwrap();
    }

    let mut bad_rsa = bytes.clone();
    // Make the first encrypted MPI octet a noncanonical leading zero.
    let mpi_start = bytes.len() - input.len() - 256;
    bad_rsa[mpi_start] = 0;
    let rsa_error = provider
        .decrypt(&recipient, &mut bad_rsa.as_slice(), &config)
        .unwrap_err();

    let mut bad_mdc = bytes.clone();
    *bad_mdc.last_mut().unwrap() ^= 1;
    let mdc_error = provider
        .decrypt(&recipient, &mut bad_mdc.as_slice(), &config)
        .unwrap_err();
    assert_eq!(rsa_error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(rsa_error.to_string(), mdc_error.to_string());

    let mut changed_rsa = bytes.clone();
    changed_rsa[mpi_start + 255] ^= 1;
    let changed_error = provider
        .decrypt(&recipient, &mut changed_rsa.as_slice(), &config)
        .unwrap_err();
    assert_eq!(changed_error.to_string(), mdc_error.to_string());

    let mut truncated = &bytes[..bytes.len() - 1];
    assert!(
        provider
            .decrypt(&recipient, &mut truncated, &config)
            .is_err()
    );
    let config = DecodingConfig {
        max_body_len: 100,
        ..config
    };
    assert!(
        provider
            .decrypt(&recipient, &mut bytes.as_slice(), &config)
            .is_err()
    );
}
