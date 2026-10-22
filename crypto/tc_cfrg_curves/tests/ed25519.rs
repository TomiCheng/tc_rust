use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_cfrg_curves::{
    CfrgError, Ed25519CtxSigner, Ed25519KeyPairGenerator, Ed25519PhSigner, Ed25519PrivateKey,
    Ed25519PublicKey, Ed25519Signer, KeyGenerationParams,
};
use tc_signer::{Signer, SignerInit};

include!("data/ed25519/vectors.rs");
include!("data/ed25519/taming.rs");
include!("data/ed25519/public_keys.rs");

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn key(text: &str) -> [u8; 32] {
    hex(text).try_into().unwrap()
}

fn sign<S>(mut signer: S, private_key: &Ed25519PrivateKey, message: &[u8]) -> [u8; 64]
where
    S: Signer<Error = CfrgError> + SignerInit<Ed25519PrivateKey, Error = CfrgError>,
{
    SignerInit::<Ed25519PrivateKey>::init(&mut signer, private_key).unwrap();
    signer.update(message).unwrap();
    let mut signature = [0; 64];
    assert_eq!(signer.generate_signature(&mut signature), Ok(64));
    signature
}

fn verify<S>(mut signer: S, public_key: &Ed25519PublicKey, message: &[u8], signature: &[u8]) -> bool
where
    S: Signer<Error = CfrgError> + SignerInit<Ed25519PublicKey, Error = CfrgError>,
{
    if SignerInit::<Ed25519PublicKey>::init(&mut signer, public_key).is_err() {
        return false;
    }
    signer.update(message).unwrap();
    signer.verify_signature(signature).unwrap()
}

// Signs a vector's message, checks the expected signature, and verifies it and its corruptions.
fn check<S, F>(
    make: F,
    private_key: &[u8; 32],
    public_key: &[u8; 32],
    message: &[u8],
    expected: &[u8; 64],
    label: &str,
) where
    S: Signer<Error = CfrgError>
        + SignerInit<Ed25519PrivateKey, Error = CfrgError>
        + SignerInit<Ed25519PublicKey, Error = CfrgError>,
    F: Fn() -> S,
{
    let private_key = Ed25519PrivateKey::new(*private_key);
    let public_key = Ed25519PublicKey::new(*public_key);
    assert_eq!(private_key.generate_public_key(), public_key, "{label}");
    assert_eq!(&sign(make(), &private_key, message), expected, "{label}");
    assert!(verify(make(), &public_key, message, expected), "{label}");
    for byte in [0, 31, 32, 63] {
        let mut bad = *expected;
        bad[byte] ^= 1;
        assert!(
            !verify(make(), &public_key, message, &bad),
            "{label} corrupt {byte}"
        );
    }
}

// RFC 8032 §7.1 to §7.3: Ed25519, Ed25519ctx and Ed25519ph, as BC's Ed25519Test runs them.
#[test]
fn every_rfc_8032_vector_signs_and_verifies() {
    for &(mode, sk, pk, message, context, signature, label) in VECTORS {
        let (sk, pk, message, context) = (key(sk), key(pk), hex(message), hex(context));
        let signature: [u8; 64] = hex(signature).try_into().unwrap();
        match mode {
            0 => check(Ed25519Signer::new, &sk, &pk, &message, &signature, label),
            1 => check(
                || Ed25519CtxSigner::new(&context),
                &sk,
                &pk,
                &message,
                &signature,
                label,
            ),
            _ => check(
                || Ed25519PhSigner::new(&context),
                &sk,
                &pk,
                &message,
                &signature,
                label,
            ),
        }
    }
}

// "Taming the many EdDSAs": BC's policy, canonical encodings, no small-order public key, and
// the cofactored equation. A public key BC refuses never verifies.
#[test]
fn verification_follows_bcs_taming_policy() {
    for &(number, expected, message, pk, signature) in TAMING {
        if signature.len() != 128 {
            assert!(!expected, "Taming #{number}");
            continue;
        }
        let public_key = Ed25519PublicKey::new(key(pk));
        let actual = verify(
            Ed25519Signer::new(),
            &public_key,
            &hex(message),
            &hex(signature),
        );
        assert_eq!(actual, expected, "Taming #{number}");
    }
}

// BC's partial validation of public keys, which init applies.
#[test]
fn init_refuses_the_public_keys_bc_refuses() {
    for &(full, expected, pk) in PUBLIC_KEYS {
        if full {
            continue;
        }
        let mut signer = Ed25519Signer::new();
        let result =
            SignerInit::<Ed25519PublicKey>::init(&mut signer, &Ed25519PublicKey::new(key(pk)));
        assert_eq!(result.is_ok(), expected, "{pk}");
        if !expected {
            assert_eq!(result, Err(CfrgError::InvalidPublicKey));
        }
    }
}

#[test]
fn signatures_do_not_cross_domains_or_messages() {
    let private_key = Ed25519PrivateKey::new([7; 32]);
    let public_key = private_key.generate_public_key();
    let signature = sign(Ed25519Signer::new(), &private_key, b"message");
    assert!(verify(
        Ed25519Signer::new(),
        &public_key,
        b"message",
        &signature
    ));
    assert!(!verify(
        Ed25519Signer::new(),
        &public_key,
        b"other",
        &signature
    ));
    assert!(!verify(
        Ed25519CtxSigner::new(b""),
        &public_key,
        b"message",
        &signature
    ));
    assert!(!verify(
        Ed25519PhSigner::new(b""),
        &public_key,
        b"message",
        &signature
    ));

    let mut malleable = signature;
    malleable[32..].fill(255);
    assert!(!verify(
        Ed25519Signer::new(),
        &public_key,
        b"message",
        &malleable
    ));
    assert!(!verify(
        Ed25519Signer::new(),
        &public_key,
        b"message",
        &signature[..63]
    ));
}

#[test]
fn contexts_up_to_255_bytes_are_taken_at_init() {
    let private_key = Ed25519PrivateKey::new([7; 32]);
    let public_key = private_key.generate_public_key();
    let signature = sign(Ed25519CtxSigner::new(&[1; 255]), &private_key, b"message");
    assert!(verify(
        Ed25519CtxSigner::new(&[1; 255]),
        &public_key,
        b"message",
        &signature
    ));

    let mut signer = Ed25519CtxSigner::new(&[0; 256]);
    assert_eq!(
        SignerInit::<Ed25519PrivateKey>::init(&mut signer, &private_key),
        Err(CfrgError::ContextTooLong)
    );
    let mut signer = Ed25519PhSigner::new(&[0; 256]);
    assert_eq!(
        SignerInit::<Ed25519PublicKey>::init(&mut signer, &public_key),
        Err(CfrgError::ContextTooLong)
    );
}

#[test]
fn a_signer_refuses_the_wrong_mode_a_missing_init_and_a_short_output() {
    let private_key = Ed25519PrivateKey::new([7; 32]);
    let public_key = private_key.generate_public_key();
    let mut signature = [0; 64];

    let mut signer = Ed25519Signer::new();
    assert_eq!(
        signer.generate_signature(&mut signature),
        Err(CfrgError::NotInitialized)
    );
    assert_eq!(
        signer.verify_signature(&signature),
        Err(CfrgError::NotInitialized)
    );

    SignerInit::<Ed25519PrivateKey>::init(&mut signer, &private_key).unwrap();
    assert_eq!(
        signer.verify_signature(&signature),
        Err(CfrgError::NotForVerifying)
    );
    assert_eq!(
        signer.generate_signature(&mut [0; 63]),
        Err(CfrgError::OutputTooShort)
    );

    SignerInit::<Ed25519PublicKey>::init(&mut signer, &public_key).unwrap();
    assert_eq!(
        signer.generate_signature(&mut signature),
        Err(CfrgError::NotForSigning)
    );
}

// A signature resets the signer, so the next one covers only the next message.
#[test]
fn a_signer_starts_afresh_after_each_signature() {
    let private_key = Ed25519PrivateKey::new([7; 32]);
    let mut signer = Ed25519Signer::new();
    SignerInit::<Ed25519PrivateKey>::init(&mut signer, &private_key).unwrap();
    let mut first = [0; 64];
    signer.update(b"one").unwrap();
    signer.generate_signature(&mut first).unwrap();
    let mut second = [0; 64];
    signer.update(b"two").unwrap();
    signer.generate_signature(&mut second).unwrap();
    assert_eq!(first, sign(Ed25519Signer::new(), &private_key, b"one"));
    assert_eq!(second, sign(Ed25519Signer::new(), &private_key, b"two"));
}

#[test]
fn generated_key_pairs_sign_and_verify() {
    let mut rng = rand::rng();
    let mut generator = Ed25519KeyPairGenerator::new();
    generator.init(KeyGenerationParams::new(&mut rng)).unwrap();
    let (public_key, private_key) = generator.generate_key_pair().unwrap();
    assert_eq!(private_key.generate_public_key(), public_key);
    let signature = sign(Ed25519Signer::new(), &private_key, b"message");
    assert!(verify(
        Ed25519Signer::new(),
        &public_key,
        b"message",
        &signature
    ));
}
