#![cfg(feature = "legacy-encryption")]

use tc_openpgp::{
    DefaultPgpOperatorBuilder, PgpOperator, PgpOperatorBuilder, PgpRsaSecretKeys, SecretKeyLimits,
};
use tc_openpgp_packet::{ArmorKind, AsciiArmor, DecodingConfig, PacketTag, PgpReader};

// GnuPG 2.4.9 exported this disposable RSA primary and encryption subkey
// using CFB protection with iterated-and-salted S2K.
const PROTECTED_KEY: &str = include_str!("fixtures/rsa_v4_protected.asc");
const PASSPHRASE: &[u8] = b"OpenPGP disposable fixture passphrase";
const MESSAGES: [&str; 3] = [
    include_str!("fixtures/rsa_v3_aes128.asc"),
    include_str!("fixtures/rsa_v3_aes192.asc"),
    include_str!("fixtures/rsa_v3_aes256.asc"),
];
const EXPECTED: &[u8] = &[0, 42, 13, 10, 127, 128, 255];

fn test_keys(operator: &dyn PgpOperator) -> PgpRsaSecretKeys {
    operator
        .secret_key()
        .import_v4_rsa_armored(
            PROTECTED_KEY,
            PASSPHRASE,
            &DecodingConfig::default(),
            &SecretKeyLimits::default(),
        )
        .unwrap()
}

#[test]
fn rejects_wrong_passphrase_corruption_and_excess_secret_keys() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let provider = operator.secret_key();
    let config = DecodingConfig::default();
    let limits = SecretKeyLimits::default();
    let binary = AsciiArmor::decode(ArmorKind::PrivateKey, PROTECTED_KEY).unwrap();
    let wrong = provider
        .import_v4_rsa(&binary, b"wrong", &config, &limits)
        .err()
        .unwrap();
    assert_eq!(wrong.kind(), std::io::ErrorKind::InvalidData);
    let mut remaining = binary.as_slice();
    {
        let mut reader = PgpReader::new(&mut remaining);
        let (header, mut body) = reader.read_body(&config).unwrap();
        assert_eq!(header.tag(), PacketTag::SecretKey);
        std::io::copy(&mut body, &mut std::io::sink()).unwrap();
    }
    let last_secret_byte = binary.len() - remaining.len() - 1;
    let mut corrupt = binary.clone();
    corrupt[last_secret_byte] ^= 1;
    let corruption = provider
        .import_v4_rsa(&corrupt, PASSPHRASE, &config, &limits)
        .err()
        .unwrap();
    assert_eq!(wrong.to_string(), corruption.to_string());
    let limits = SecretKeyLimits {
        max_keys: 1,
        ..limits
    };
    assert!(
        provider
            .import_v4_rsa(&binary, PASSPHRASE, &config, &limits)
            .is_err()
    );
}

#[test]
fn decrypts_gnupg_rsa_messages_with_all_aes_key_sizes_and_compression_modes() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let keys = test_keys(&*operator);
    assert_eq!(keys.subkeys().len(), 1);
    let recipient = &keys.subkeys()[0];
    let compressed = [
        include_str!("fixtures/rsa_v3_zip.asc"),
        include_str!("fixtures/rsa_v3_zlib.asc"),
    ];
    for armor in MESSAGES.into_iter().chain(compressed) {
        let mut bytes = AsciiArmor::decode(ArmorKind::Message, armor).unwrap();
        bytes.extend_from_slice(b"next");
        let mut input = bytes.as_slice();
        let literal = operator
            .encrypted_message()
            .decrypt(recipient, &mut input, &DecodingConfig::default())
            .unwrap();
        assert_eq!(literal.filename(), b"document.bin");
        assert_eq!(literal.data(), EXPECTED);
        assert_eq!(input, b"next");
    }
}

#[test]
fn rsa_and_mdc_failures_reject_plaintext_with_the_same_error() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let keys = test_keys(&*operator);
    assert_eq!(keys.subkeys().len(), 1);
    let recipient = &keys.subkeys()[0];
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
        .decrypt(recipient, &mut bad_rsa.as_slice(), &config)
        .unwrap_err();

    let mut bad_mdc = bytes.clone();
    *bad_mdc.last_mut().unwrap() ^= 1;
    let mdc_error = provider
        .decrypt(recipient, &mut bad_mdc.as_slice(), &config)
        .unwrap_err();
    assert_eq!(rsa_error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(rsa_error.to_string(), mdc_error.to_string());

    let mut changed_rsa = bytes.clone();
    changed_rsa[mpi_start + 255] ^= 1;
    let changed_error = provider
        .decrypt(recipient, &mut changed_rsa.as_slice(), &config)
        .unwrap_err();
    assert_eq!(changed_error.to_string(), mdc_error.to_string());

    let mut truncated = &bytes[..bytes.len() - 1];
    assert!(
        provider
            .decrypt(recipient, &mut truncated, &config)
            .is_err()
    );
    let config = DecodingConfig {
        max_body_len: 100,
        ..config
    };
    assert!(
        provider
            .decrypt(recipient, &mut bytes.as_slice(), &config)
            .is_err()
    );
}
