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
