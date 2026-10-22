#![cfg(feature = "x448")]

use tc_agreement::{Agreement, AgreementInit};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_cfrg_curves::{
    CfrgError, KeyGenerationParams, X448Agreement, X448KeyPairGenerator, X448PrivateKey,
    X448PublicKey,
};

fn hex(text: &str) -> [u8; 56] {
    let mut out = [0; 56];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn agree(private_key: &X448PrivateKey, public_key: &X448PublicKey) -> Result<[u8; 56], CfrgError> {
    let mut agreement = X448Agreement::new();
    agreement.init(private_key)?;
    let mut secret = [0; 56];
    agreement.calculate_agreement(public_key, &mut secret)?;
    Ok(secret)
}

// RFC 7748 §6.2: both public keys, and the shared secret from either side.
#[test]
fn alice_and_bob_reach_the_rfc_7748_shared_secret() {
    let alice = X448PrivateKey::new(hex(
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
    ));
    let bob = X448PrivateKey::new(hex(
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
    ));
    assert_eq!(
        alice.generate_public_key().u(),
        &hex(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
        )
    );
    assert_eq!(
        bob.generate_public_key().u(),
        &hex(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
        )
    );

    let shared = hex(
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
    );
    assert_eq!(agree(&alice, &bob.generate_public_key()), Ok(shared));
    assert_eq!(agree(&bob, &alice.generate_public_key()), Ok(shared));
}

#[test]
fn generated_key_pairs_agree_with_each_other() {
    let mut rng = rand::rng();
    let mut generator = X448KeyPairGenerator::new();
    generator.init(KeyGenerationParams::new(&mut rng)).unwrap();
    let (alice_public, alice) = generator.generate_key_pair().unwrap();
    let (bob_public, bob) = generator.generate_key_pair().unwrap();
    assert_eq!(&alice.generate_public_key(), &alice_public);
    assert_eq!(agree(&alice, &bob_public), agree(&bob, &alice_public));
}

#[test]
fn a_zero_shared_secret_or_a_short_output_is_refused() {
    let alice = X448PrivateKey::new(hex(
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
    ));
    assert_eq!(
        agree(&alice, &X448PublicKey::new([0; 56])),
        Err(CfrgError::AgreementFailed)
    );

    let mut agreement = X448Agreement::new();
    let mut short = [0; 56 - 1];
    let bob_public = X448PublicKey::new(hex(
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
    ));
    assert_eq!(
        agreement.calculate_agreement(&bob_public, &mut short),
        Err(CfrgError::NotInitialized)
    );
    agreement.init(&alice).unwrap();
    assert_eq!(
        agreement.calculate_agreement(&bob_public, &mut short),
        Err(CfrgError::OutputTooShort)
    );
}

#[test]
fn an_uninitialized_generator_is_refused() {
    let mut generator = X448KeyPairGenerator::new();
    assert_eq!(
        generator.generate_key_pair().err(),
        Some(CfrgError::NotInitialized)
    );
}
