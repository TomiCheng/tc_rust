#![cfg(feature = "encryption")]

use tc_algo::params::key::X25519PrivateKey;
use tc_openpgp::{
    DefaultPgpOperatorBuilder, PgpKeyPair, PgpOperatorBuilder, PgpPrivateKey, PgpPublicKey,
};
use tc_openpgp_packet::{
    ArmorKind, AsciiArmor, DecodingConfig, LiteralData, PublicKeyAlgorithmTag, PublicKeyVersion,
};

#[test]
fn x25519_round_trips_multiple_chunks_and_rejects_invalid_messages() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let mut generator = operator
        .key_pair_generator()
        .get_by_algorithm(PublicKeyAlgorithmTag::X25519)
        .unwrap();
    let keys = generator.generate().unwrap();
    let other_keys = generator.generate().unwrap();
    let provider = operator.encrypted_message();

    let payload = vec![0x42; 9000];
    let mut literal = LiteralData::with_data(&payload);
    literal.set_filename("payload.bin").unwrap();
    literal.set_timestamp(1234);
    let mut message = Vec::new();
    provider
        .encrypt(keys.public(), &literal, &mut message)
        .unwrap();

    let config = DecodingConfig::default();
    let mut framed = message.clone();
    framed.extend_from_slice(b"next");
    let mut input = framed.as_slice();
    let actual = provider.decrypt(&keys, &mut input, &config).unwrap();
    assert_eq!(actual, literal);
    assert_eq!(input, b"next");

    let result = provider.decrypt(&other_keys, &mut message.as_slice(), &config);
    assert!(result.is_err());
    let config = DecodingConfig {
        max_body_len: 4096,
        ..config
    };
    assert!(
        provider
            .decrypt(&keys, &mut message.as_slice(), &config)
            .is_err()
    );
    *message.last_mut().unwrap() ^= 1;
    assert!(
        provider
            .decrypt(&keys, &mut message.as_slice(), &DecodingConfig::default())
            .is_err()
    );
}

#[test]
fn decrypts_rfc_9580_appendix_a8() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let private = X25519PrivateKey::new([
        0x4d, 0x60, 0x0a, 0x4f, 0x79, 0x4d, 0x44, 0x77, 0x5c, 0x57, 0xa2, 0x6e, 0x0f, 0xee, 0xfe,
        0xd5, 0x58, 0xe9, 0xaf, 0xff, 0xd6, 0xad, 0x0d, 0x58, 0x2d, 0x57, 0xfb, 0x2b, 0xa2, 0xdc,
        0xed, 0xb8,
    ]);
    let algorithm = PublicKeyAlgorithmTag::X25519;
    let keys = PgpKeyPair::new(
        PgpPublicKey::new_with_metadata(
            algorithm,
            Box::new(private.generate_public_key()),
            PublicKeyVersion::V6,
            0x6387_7fe3,
        ),
        PgpPrivateKey::new(algorithm, Box::new(private)),
    );
    let armor = concat!(
        "-----BEGIN PGP MESSAGE-----\n\n",
        "wV0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmHzxjV8bU/gXzO\n",
        "WgBM85PMiVi93AZfJfhK9QmxfdNnZBjeo1VDeVZheQHgaVf7yopqR6W1FT6NOrfS\n",
        "aQIHAgZhZBZTW+CwcW1g4FKlbExAf56zaw76/prQoN+bAzxpohup69LA7JW/Vp0l\n",
        "yZnuSj3hcFj0DfqLTGgr4/u717J+sPWbtQBfgMfG9AOIwwrUBqsFE9zW+f1zdlYo\n",
        "bhF30A+IitsxxA==\n",
        "-----END PGP MESSAGE-----\n",
    );
    let message = AsciiArmor::decode(ArmorKind::Message, armor).unwrap();
    let literal = operator
        .encrypted_message()
        .decrypt(&keys, &mut message.as_slice(), &DecodingConfig::default())
        .unwrap();
    assert_eq!(literal.data(), b"Hello, world!");
}

#[test]
fn all_addressed_recipients_can_decrypt_the_same_message() {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let mut generator = operator
        .key_pair_generator()
        .get_by_algorithm(PublicKeyAlgorithmTag::X25519)
        .unwrap();
    let first = generator.generate().unwrap();
    let second = generator.generate().unwrap();
    let other = generator.generate().unwrap();
    let provider = operator.encrypted_message();
    // Three header bytes and six metadata bytes bring this to one exact 4096-byte OCB chunk.
    let literal = LiteralData::with_data(&vec![7; 4096 - 9]);
    let mut bytes = Vec::new();
    assert!(provider.encrypt_to_many(&[], &literal, &mut bytes).is_err());
    assert!(bytes.is_empty());
    provider
        .encrypt_to_many(&[first.public(), second.public()], &literal, &mut bytes)
        .unwrap();

    let config = DecodingConfig::default();
    for recipient in [&first, &second] {
        let result = provider
            .decrypt(recipient, &mut bytes.as_slice(), &config)
            .unwrap();
        assert_eq!(result, literal);
    }
    assert!(
        provider
            .decrypt(&other, &mut bytes.as_slice(), &config)
            .is_err()
    );
}

#[test]
fn signs_and_encrypts_to_certified_recipients_and_rejects_a_different_primary() {
    use tc_openpgp::PgpKeyPair;

    let operator = DefaultPgpOperatorBuilder::default().build();
    let generate = |algorithm| -> PgpKeyPair {
        operator
            .key_pair_generator()
            .get_by_algorithm(algorithm)
            .unwrap()
            .generate()
            .unwrap()
    };
    let signer = generate(PublicKeyAlgorithmTag::Ed25519);
    let alice = generate(PublicKeyAlgorithmTag::Ed25519);
    let bob = generate(PublicKeyAlgorithmTag::Ed25519);
    let other = generate(PublicKeyAlgorithmTag::Ed25519);
    let alice_subkey = generate(PublicKeyAlgorithmTag::X25519);
    let bob_subkey = generate(PublicKeyAlgorithmTag::X25519);
    let time = [
        signer.public(),
        alice.public(),
        bob.public(),
        other.public(),
        alice_subkey.public(),
        bob_subkey.public(),
    ]
    .into_iter()
    .map(|key| key.creation_time())
    .max()
    .unwrap();
    let certificates = operator.certificate();
    let alice = certificates
        .create(&alice, &[], &[alice_subkey.public()], time)
        .unwrap();
    let bob = certificates
        .create(&bob, &[], &[bob_subkey.public()], time)
        .unwrap();
    // The same private subkey can open the ciphertext, but the signature
    // must remain bound to Alice's primary key rather than this certificate.
    let substitute = certificates
        .create(&other, &[], &[alice_subkey.public()], time)
        .unwrap();

    let literal = LiteralData::with_data(&vec![0xa3; 9000]);
    let encryption = operator.encrypted_message();
    let config = DecodingConfig::default();
    let mut bytes = Vec::new();
    encryption
        .sign_and_encrypt(&signer, &[&alice, &bob], &literal, time, &mut bytes)
        .unwrap();
    for (key, certificate) in [(&alice_subkey, &alice), (&bob_subkey, &bob)] {
        let data = encryption
            .decrypt_and_verify(
                key,
                certificate,
                signer.public(),
                &mut bytes.as_slice(),
                &config,
            )
            .unwrap();
        assert_eq!(data, literal);
    }
    for (certificate, verifier) in [(&substitute, signer.public()), (&alice, other.public())] {
        assert!(
            encryption
                .decrypt_and_verify(
                    &alice_subkey,
                    certificate,
                    verifier,
                    &mut bytes.as_slice(),
                    &config
                )
                .is_err()
        );
    }
    let mut changed = bytes;
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        encryption
            .decrypt_and_verify(
                &alice_subkey,
                &alice,
                signer.public(),
                &mut changed.as_slice(),
                &config
            )
            .is_err()
    );
}
