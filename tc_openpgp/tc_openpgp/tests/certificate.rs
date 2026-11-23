#![cfg(feature = "cfrg-curves")]

use tc_openpgp::{DefaultPgpOperatorBuilder, PgpOperatorBuilder};
use tc_openpgp_packet::{ArmorKind, AsciiArmor, DecodingConfig, PublicKeyAlgorithmTag};

#[test]
fn generated_certificate_round_trips_and_detects_tampered_id_and_subkey() {
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
    let provider = operator.certificate();
    let user_ids = ["Alice <alice@example.org>", "王小明 <alice@example.com>"];
    let now = primary
        .public()
        .creation_time()
        .max(subkey.public().creation_time());
    let certificate = provider
        .create(&primary, &user_ids, &[subkey.public()], now)
        .unwrap();
    let bytes = provider.encode(&certificate).unwrap();
    let armored = provider.encode_armored(&certificate).unwrap();
    let config = DecodingConfig::default();
    let decoded = provider.decode_armored(&armored, &config).unwrap();

    assert_eq!(provider.encode(&decoded).unwrap(), bytes);
    assert_eq!(
        decoded
            .user_ids()
            .iter()
            .map(|id| id.value())
            .collect::<Vec<_>>(),
        user_ids
    );
    assert_eq!(decoded.subkeys().len(), 1);
    assert_eq!(
        operator
            .serializer()
            .encode(decoded.subkeys()[0].key())
            .unwrap(),
        operator.serializer().encode(subkey.public()).unwrap()
    );

    let mut changed = bytes.clone();
    let pos = bytes
        .windows(user_ids[0].len())
        .position(|part| part == user_ids[0].as_bytes())
        .unwrap();
    changed[pos] ^= 1;
    assert!(provider.decode(&changed, &config).is_err());

    let mut changed = bytes.clone();
    let public_packet = operator.serializer().encode(subkey.public()).unwrap();
    let public_body = &public_packet[2..];
    let pos = bytes
        .windows(public_body.len())
        .position(|part| part == public_body)
        .unwrap();
    changed[pos + public_body.len() - 1] ^= 1;
    assert!(provider.decode(&changed, &config).is_err());
    assert!(provider.decode(&bytes[..bytes.len() - 1], &config).is_err());

    let key_only = operator.serializer().encode(primary.public()).unwrap();
    assert!(provider.decode(&key_only, &config).is_err());
    let config = DecodingConfig {
        max_body_len: 42,
        ..config
    };
    assert!(provider.decode(&bytes, &config).is_err());
}

#[test]
fn imports_and_verifies_rfc_9580_appendix_a3() {
    let armor = concat!(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n",
        "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf\n",
        "GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy\n",
        "KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw\n",
        "gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE\n",
        "QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn\n",
        "+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh\n",
        "BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8\n",
        "j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805\n",
        "I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==\n",
        "-----END PGP PUBLIC KEY BLOCK-----\n",
    );
    let operator = DefaultPgpOperatorBuilder::default().build();
    let provider = operator.certificate();
    let certificate = provider
        .decode_armored(armor, &DecodingConfig::default())
        .unwrap();
    assert_eq!(
        certificate.primary_key().algorithm(),
        PublicKeyAlgorithmTag::Ed25519
    );
    assert!(certificate.user_ids().is_empty());
    assert_eq!(certificate.subkeys().len(), 1);
    assert_eq!(
        certificate.subkeys()[0].key().algorithm(),
        PublicKeyAlgorithmTag::X25519
    );
    assert_eq!(
        provider.encode(&certificate).unwrap(),
        AsciiArmor::decode(ArmorKind::PublicKey, armor).unwrap()
    );
}

#[test]
fn verified_revocations_disable_key_selection_and_survive_round_trip() {
    use tc_algo::params::key::{Ed25519PrivateKey, X25519PrivateKey};
    use tc_openpgp::{
        PgpEncryptionPurpose, PgpKeyPair, PgpKeyRevocationReason, PgpPrivateKey, PgpPublicKey,
    };
    use tc_openpgp_packet::{EncodingConfig, PgpWrite, PublicKeyVersion};

    fn primary(seed: u8) -> PgpKeyPair {
        let secret = Ed25519PrivateKey::new([seed; 32]);
        let tag = PublicKeyAlgorithmTag::Ed25519;
        PgpKeyPair::new(
            PgpPublicKey::new_with_metadata(
                tag,
                Box::new(secret.generate_public_key()),
                PublicKeyVersion::V6,
                100,
            ),
            PgpPrivateKey::new(tag, Box::new(secret)),
        )
    }
    fn subkey(seed: u8, time: u32) -> PgpKeyPair {
        let secret = X25519PrivateKey::new([seed; 32]);
        let tag = PublicKeyAlgorithmTag::X25519;
        PgpKeyPair::new(
            PgpPublicKey::new_with_metadata(
                tag,
                Box::new(secret.generate_public_key()),
                PublicKeyVersion::V6,
                time,
            ),
            PgpPrivateKey::new(tag, Box::new(secret)),
        )
    }

    let operator = DefaultPgpOperatorBuilder::default().build();
    let provider = operator.certificate();
    let primary = primary(1);
    let old = subkey(10, 101);
    let recent = subkey(20, 102);
    let purpose = PgpEncryptionPurpose::Communications;
    let config = DecodingConfig::default();
    let mut certificate = provider
        .create(&primary, &[], &[old.public(), recent.public()], 110)
        .unwrap();
    assert!(certificate.signing_key_at(109).is_none());
    assert_eq!(
        certificate
            .encryption_key_at(120, purpose)
            .unwrap()
            .creation_time(),
        102
    );

    provider
        .revoke_subkey(
            &mut certificate,
            &primary,
            1,
            PgpKeyRevocationReason::Retired,
            130,
        )
        .unwrap();
    let certificate_bytes = provider.encode(&certificate).unwrap();
    let mut certificate = provider.decode(&certificate_bytes, &config).unwrap();
    assert_eq!(certificate.subkeys()[1].revocations().count(), 1);
    assert_eq!(
        certificate
            .encryption_key_at(129, purpose)
            .unwrap()
            .creation_time(),
        102
    );
    let selected = certificate.encryption_key_at(130, purpose).unwrap();
    assert_eq!(selected.creation_time(), 101);

    #[cfg(feature = "encryption")]
    {
        let encryption = operator.encrypted_message();
        let literal = tc_openpgp_packet::LiteralData::with_str("the selected key works");
        let mut message = Vec::new();
        encryption
            .encrypt_to_many(&[selected], &literal, &mut message)
            .unwrap();
        assert_eq!(
            encryption
                .decrypt(&old, &mut message.as_slice(), &config)
                .unwrap(),
            literal
        );
        assert!(
            encryption
                .decrypt(&recent, &mut message.as_slice(), &config)
                .is_err()
        );
    }

    let mut revoked = provider.decode(&certificate_bytes, &config).unwrap();
    provider
        .revoke_primary(
            &mut revoked,
            &primary,
            PgpKeyRevocationReason::Compromised,
            140,
        )
        .unwrap();
    let encoded = provider.encode(&revoked).unwrap();
    let decoded = provider.decode(&encoded, &config).unwrap();
    assert!(decoded.is_revoked_at(120));
    assert!(decoded.signing_key_at(150).is_none());
    assert!(decoded.encryption_key_at(150, purpose).is_none());
    assert_eq!(provider.encode(&decoded).unwrap(), encoded);

    let mut standalone = operator.serializer().encode(primary.public()).unwrap();
    revoked
        .revocations()
        .next()
        .unwrap()
        .encode(&mut standalone, &EncodingConfig::default())
        .unwrap();
    let mut changed = standalone.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        provider
            .apply_primary_revocation(&mut certificate, &changed, &config)
            .is_err()
    );
    assert!(!certificate.is_revoked_at(150));
    provider
        .apply_primary_revocation(&mut certificate, &standalone, &config)
        .unwrap();
    provider
        .apply_primary_revocation(&mut certificate, &standalone, &config)
        .unwrap();
    assert_eq!(certificate.revocations().count(), 1);
    assert!(certificate.is_revoked_at(150));
}
