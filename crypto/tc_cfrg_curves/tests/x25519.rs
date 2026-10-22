use tc_agreement::{Agreement, AgreementInit};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_cfrg_curves::{
    CfrgError, KeyGenerationParams, X25519Agreement, X25519KeyPairGenerator, X25519PrivateKey,
    X25519PublicKey,
};

fn hex(text: &str) -> [u8; 32] {
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn agree(
    private_key: &X25519PrivateKey,
    public_key: &X25519PublicKey,
) -> Result<[u8; 32], CfrgError> {
    let mut agreement = X25519Agreement::new();
    agreement.init(private_key)?;
    let mut secret = [0; 32];
    agreement.calculate_agreement(public_key, &mut secret)?;
    Ok(secret)
}

// RFC 7748 §6.1: both public keys, and the shared secret from either side.
#[test]
fn alice_and_bob_reach_the_rfc_7748_shared_secret() {
    let alice = X25519PrivateKey::new(hex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let bob = X25519PrivateKey::new(hex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));
    assert_eq!(
        alice.generate_public_key().u(),
        &hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        bob.generate_public_key().u(),
        &hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    );

    let shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(agree(&alice, &bob.generate_public_key()), Ok(shared));
    assert_eq!(agree(&bob, &alice.generate_public_key()), Ok(shared));
}

#[test]
fn generated_key_pairs_agree_with_each_other() {
    let mut rng = rand::rng();
    let mut generator = X25519KeyPairGenerator::new();
    generator.init(KeyGenerationParams::new(&mut rng)).unwrap();
    let (alice_public, alice) = generator.generate_key_pair().unwrap();
    let (bob_public, bob) = generator.generate_key_pair().unwrap();
    assert_eq!(&alice.generate_public_key(), &alice_public);
    assert_eq!(agree(&alice, &bob_public), agree(&bob, &alice_public));
}

#[test]
fn a_zero_shared_secret_or_a_short_output_is_refused() {
    let alice = X25519PrivateKey::new(hex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    assert_eq!(
        agree(&alice, &X25519PublicKey::new([0; 32])),
        Err(CfrgError::AgreementFailed)
    );

    let mut agreement = X25519Agreement::new();
    let mut short = [0; 32 - 1];
    let bob_public = X25519PublicKey::new(hex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
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
    let mut generator = X25519KeyPairGenerator::new();
    assert_eq!(
        generator.generate_key_pair().err(),
        Some(CfrgError::NotInitialized)
    );
}
