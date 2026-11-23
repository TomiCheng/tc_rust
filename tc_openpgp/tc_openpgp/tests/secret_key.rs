#![cfg(feature = "secret-key")]

use tc_openpgp::{DefaultPgpOperatorBuilder, PgpOperatorBuilder, SecretKeyLimits};
use tc_openpgp_packet::{ArmorKind, AsciiArmor, DecodingConfig, PublicKeyAlgorithmTag};

#[test]
fn protected_certificate_round_trips_and_rejects_wrong_passphrase_and_excessive_work() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let generator = operator.key_pair_generator();
    let primary = generator
        .get_by_algorithm(PublicKeyAlgorithmTag::Ed25519)
        .unwrap()
        .generate()
        .unwrap();
    let subkey = generator
        .get_by_algorithm(PublicKeyAlgorithmTag::X25519)
        .unwrap()
        .generate()
        .unwrap();
    let now = primary
        .public()
        .creation_time()
        .max(subkey.public().creation_time());
    let certificate = operator
        .certificate()
        .create(
            &primary,
            &["Alice <alice@example.org>"],
            &[subkey.public()],
            now,
        )
        .unwrap();
    let provider = operator.secret_key();
    let passphrase = b"integration test passphrase";
    assert!(
        provider
            .export_armored(&certificate, &primary, &[], passphrase)
            .is_err()
    );
    let armor = provider
        .export_armored(&certificate, &primary, &[&subkey], passphrase)
        .unwrap();
    let config = DecodingConfig::default();
    let limits = SecretKeyLimits::default();
    let imported = provider
        .import_armored(&armor, passphrase, &config, &limits)
        .unwrap();
    assert_eq!(
        operator.certificate().encode(&certificate).unwrap(),
        operator
            .certificate()
            .encode(imported.certificate())
            .unwrap(),
    );
    assert_eq!(imported.subkeys().len(), 1);

    let data = b"private key survives a protected round trip";
    let signatures = operator.detached_signature();
    let signature = signatures
        .sign(imported.primary(), &mut data.as_slice(), now)
        .unwrap();
    assert!(
        signatures
            .verify(primary.public(), &mut data.as_slice(), &signature)
            .unwrap()
    );

    #[cfg(feature = "encryption")]
    {
        let literal = tc_openpgp_packet::LiteralData::with_data(data);
        let encryption = operator.encrypted_message();
        let mut message = Vec::new();
        encryption
            .encrypt(subkey.public(), &literal, &mut message)
            .unwrap();
        assert_eq!(
            encryption
                .decrypt(&imported.subkeys()[0], &mut message.as_slice(), &config)
                .unwrap(),
            literal
        );
    }

    assert!(
        provider
            .import_armored(&armor, b"wrong", &config, &limits)
            .is_err()
    );
    let mut bytes = AsciiArmor::decode(ArmorKind::PrivateKey, &armor).unwrap();
    let limits = SecretKeyLimits {
        max_memory_kib: 32 * 1024,
        ..limits
    };
    let error = provider
        .import(&bytes, passphrase, &config, &limits)
        .err()
        .unwrap();
    assert!(error.to_string().contains("Argon2id parameters"));
    bytes[2 + 129] ^= 1;
    let error = provider
        .import(&bytes, passphrase, &config, &SecretKeyLimits::default())
        .err()
        .unwrap();
    assert!(error.to_string().contains("authentication failed"));
}
