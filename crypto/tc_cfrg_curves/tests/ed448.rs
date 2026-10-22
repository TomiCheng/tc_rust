#![cfg(feature = "ed448")]

use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_cfrg_curves::{
    CfrgError, Ed448KeyPairGenerator, Ed448PhSigner, Ed448PrivateKey, Ed448PublicKey, Ed448Signer,
    KeyGenerationParams,
};
use tc_signer::{Signer, SignerInit};

include!("data/ed448/vectors.rs");
include!("data/ed448/public_keys.rs");

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn key(text: &str) -> [u8; 57] {
    hex(text).try_into().unwrap()
}

fn sign<S>(mut signer: S, private_key: &Ed448PrivateKey, message: &[u8]) -> [u8; 114]
where
    S: Signer<Error = CfrgError> + SignerInit<Ed448PrivateKey, Error = CfrgError>,
{
    SignerInit::<Ed448PrivateKey>::init(&mut signer, private_key).unwrap();
    signer.update(message).unwrap();
    let mut signature = [0; 114];
    assert_eq!(signer.generate_signature(&mut signature), Ok(114));
    signature
}

fn verify<S>(mut signer: S, public_key: &Ed448PublicKey, message: &[u8], signature: &[u8]) -> bool
where
    S: Signer<Error = CfrgError> + SignerInit<Ed448PublicKey, Error = CfrgError>,
{
    if SignerInit::<Ed448PublicKey>::init(&mut signer, public_key).is_err() {
        return false;
    }
    signer.update(message).unwrap();
    signer.verify_signature(signature).unwrap()
}

// Signs a vector's message, checks the expected signature, and verifies it and its corruptions.
fn check<S, F>(
    make: F,
    private_key: &[u8; 57],
    public_key: &[u8; 57],
    message: &[u8],
    expected: &[u8; 114],
    label: &str,
) where
    S: Signer<Error = CfrgError>
        + SignerInit<Ed448PrivateKey, Error = CfrgError>
        + SignerInit<Ed448PublicKey, Error = CfrgError>,
    F: Fn() -> S,
{
    let private_key = Ed448PrivateKey::new(*private_key);
    let public_key = Ed448PublicKey::new(*public_key);
    assert_eq!(private_key.generate_public_key(), public_key, "{label}");
    assert_eq!(&sign(make(), &private_key, message), expected, "{label}");
    assert!(verify(make(), &public_key, message, expected), "{label}");
    for byte in [0, 56, 57, 113] {
        let mut bad = *expected;
        bad[byte] ^= 1;
        assert!(
            !verify(make(), &public_key, message, &bad),
            "{label} corrupt {byte}"
        );
    }
}

// RFC 8032 §7.4 and §7.5: Ed448 and Ed448ph, as BC's Ed448Test runs them.
#[test]
fn every_rfc_8032_vector_signs_and_verifies() {
    for &(mode, sk, pk, message, context, signature, label) in VECTORS {
        let (sk, pk, message, context) = (key(sk), key(pk), hex(message), hex(context));
        let signature: [u8; 114] = hex(signature).try_into().unwrap();
        if mode == 0 {
            check(
                || Ed448Signer::new(&context),
                &sk,
                &pk,
                &message,
                &signature,
                label,
            );
        } else {
            check(
                || Ed448PhSigner::new(&context),
                &sk,
                &pk,
                &message,
                &signature,
                label,
            );
        }
    }
}

// BC's partial validation of public keys, which init applies.
#[test]
fn init_refuses_the_public_keys_bc_refuses() {
    for &(full, expected, pk) in PUBLIC_KEYS {
        if full {
            continue;
        }
        let mut signer = Ed448Signer::new(b"");
        let result = SignerInit::<Ed448PublicKey>::init(&mut signer, &Ed448PublicKey::new(key(pk)));
        assert_eq!(result.is_ok(), expected, "{pk}");
        if !expected {
            assert_eq!(result, Err(CfrgError::InvalidPublicKey));
        }
    }
}

#[test]
fn signatures_do_not_cross_contexts_modes_or_messages() {
    let private_key = Ed448PrivateKey::new([7; 57]);
    let public_key = private_key.generate_public_key();
    let signature = sign(Ed448Signer::new(b"ctx"), &private_key, b"message");
    assert!(verify(
        Ed448Signer::new(b"ctx"),
        &public_key,
        b"message",
        &signature
    ));
    assert!(!verify(
        Ed448Signer::new(b"ctx"),
        &public_key,
        b"other",
        &signature
    ));
    assert!(!verify(
        Ed448Signer::new(b""),
        &public_key,
        b"message",
        &signature
    ));
    assert!(!verify(
        Ed448PhSigner::new(b"ctx"),
        &public_key,
        b"message",
        &signature
    ));

    let mut malleable = signature;
    malleable[57..].fill(255);
    assert!(!verify(
        Ed448Signer::new(b"ctx"),
        &public_key,
        b"message",
        &malleable
    ));
    assert!(!verify(
        Ed448Signer::new(b"ctx"),
        &public_key,
        b"message",
        &signature[..113]
    ));
}

#[test]
fn contexts_up_to_255_bytes_are_taken_at_init() {
    let private_key = Ed448PrivateKey::new([7; 57]);
    let public_key = private_key.generate_public_key();
    let signature = sign(Ed448Signer::new(&[1; 255]), &private_key, b"message");
    assert!(verify(
        Ed448Signer::new(&[1; 255]),
        &public_key,
        b"message",
        &signature
    ));

    let mut signer = Ed448Signer::new(&[0; 256]);
    assert_eq!(
        SignerInit::<Ed448PrivateKey>::init(&mut signer, &private_key),
        Err(CfrgError::ContextTooLong)
    );
    let mut signer = Ed448PhSigner::new(&[0; 256]);
    assert_eq!(
        SignerInit::<Ed448PublicKey>::init(&mut signer, &public_key),
        Err(CfrgError::ContextTooLong)
    );
}

#[test]
fn a_signer_refuses_the_wrong_mode_a_missing_init_and_a_short_output() {
    let private_key = Ed448PrivateKey::new([7; 57]);
    let public_key = private_key.generate_public_key();
    let mut signature = [0; 114];

    let mut signer = Ed448Signer::new(b"");
    assert_eq!(
        signer.generate_signature(&mut signature),
        Err(CfrgError::NotInitialized)
    );
    assert_eq!(
        signer.verify_signature(&signature),
        Err(CfrgError::NotInitialized)
    );

    SignerInit::<Ed448PrivateKey>::init(&mut signer, &private_key).unwrap();
    assert_eq!(
        signer.verify_signature(&signature),
        Err(CfrgError::NotForVerifying)
    );
    assert_eq!(
        signer.generate_signature(&mut [0; 113]),
        Err(CfrgError::OutputTooShort)
    );

    SignerInit::<Ed448PublicKey>::init(&mut signer, &public_key).unwrap();
    assert_eq!(
        signer.generate_signature(&mut signature),
        Err(CfrgError::NotForSigning)
    );
}

#[test]
fn generated_key_pairs_sign_and_verify() {
    let mut rng = rand::rng();
    let mut generator = Ed448KeyPairGenerator::new();
    generator.init(KeyGenerationParams::new(&mut rng)).unwrap();
    let (public_key, private_key) = generator.generate_key_pair().unwrap();
    assert_eq!(private_key.generate_public_key(), public_key);
    let signature = sign(Ed448PhSigner::new(b""), &private_key, b"message");
    assert!(verify(
        Ed448PhSigner::new(b""),
        &public_key,
        b"message",
        &signature
    ));
}
