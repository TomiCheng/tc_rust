use tc_ml_dsa::{HashMlDsaSigner, MlDsaError, MlDsaParameters, MlDsaPrivateKey, MlDsaSigner};
use tc_signer::{Signer, SignerInit};

const MESSAGE: &[u8] = b"attack at dawn";

fn key(params: MlDsaParameters) -> MlDsaPrivateKey {
    MlDsaPrivateKey::from_seed(params, [7; 32])
}

fn sign<S: Signer>(signer: &mut S, message: &[u8]) -> Vec<u8> {
    signer.update(message).unwrap();
    let mut signature = vec![0; signer.max_signature_size()];
    let length = signer.generate_signature(&mut signature).unwrap();
    signature.truncate(length);
    signature
}

fn verify<S: Signer>(verifier: &mut S, message: &[u8], signature: &[u8]) -> bool {
    verifier.update(message).unwrap();
    verifier.verify_signature(signature).unwrap()
}

#[test]
fn hedged_signatures_differ_and_all_verify() {
    for params in [
        MlDsaParameters::ML_DSA_44,
        MlDsaParameters::ML_DSA_65,
        MlDsaParameters::ML_DSA_87,
    ] {
        let private_key = key(params);
        let mut signer = MlDsaSigner::new(params, rand::rng());
        signer.init(&private_key).unwrap();
        let first = sign(&mut signer, MESSAGE);
        let second = sign(&mut signer, MESSAGE);
        assert_ne!(first, second);
        assert_eq!(first.len(), params.signature_length());

        let mut verifier = MlDsaSigner::deterministic(params);
        verifier.init(&private_key.public_key()).unwrap();
        assert!(verify(&mut verifier, MESSAGE, &first));
        assert!(verify(&mut verifier, MESSAGE, &second));
    }
}

#[test]
fn a_changed_message_context_or_signature_does_not_verify() {
    let params = MlDsaParameters::ML_DSA_44;
    let private_key = key(params);
    let mut signer = MlDsaSigner::deterministic(params);
    signer.init(&private_key).unwrap();
    let signature = sign(&mut signer, MESSAGE);

    let mut verifier = MlDsaSigner::deterministic(params);
    verifier.init(&private_key.public_key()).unwrap();
    assert!(!verify(&mut verifier, b"attack at dusk", &signature));

    let mut tampered = signature.clone();
    tampered[100] ^= 1;
    assert!(!verify(&mut verifier, MESSAGE, &tampered));
    assert!(!verify(
        &mut verifier,
        MESSAGE,
        &signature[..signature.len() - 1]
    ));

    let mut other = MlDsaSigner::deterministic(params);
    other.set_context(b"other").unwrap();
    other.init(&private_key.public_key()).unwrap();
    assert!(!verify(&mut other, MESSAGE, &signature));
}

#[test]
fn hash_ml_dsa_verifies_and_differs_from_pure_ml_dsa() {
    let params = MlDsaParameters::ML_DSA_65;
    let private_key = key(params);
    let mut signer = HashMlDsaSigner::deterministic(params);
    signer.init(&private_key).unwrap();
    let signature = sign(&mut signer, MESSAGE);
    assert_eq!(signer.name(), "ML-DSA-65-WITH-SHA512");

    let mut verifier = HashMlDsaSigner::deterministic(params);
    verifier.init(&private_key.public_key()).unwrap();
    assert!(verify(&mut verifier, MESSAGE, &signature));
    assert!(!verify(&mut verifier, b"attack at dusk", &signature));

    let mut pure = MlDsaSigner::deterministic(params);
    pure.init(&private_key.public_key()).unwrap();
    assert!(!verify(&mut pure, MESSAGE, &signature));
}

#[test]
fn the_signer_refuses_the_wrong_key_parameters_or_use() {
    let params = MlDsaParameters::ML_DSA_44;
    let mut signer = MlDsaSigner::deterministic(params);
    assert_eq!(signer.update(MESSAGE), Err(MlDsaError::NotInitialized));
    assert_eq!(
        signer.init(&key(MlDsaParameters::ML_DSA_65)),
        Err(MlDsaError::ParameterMismatch)
    );

    signer.init(&key(params).public_key()).unwrap();
    let mut signature = vec![0; params.signature_length()];
    assert_eq!(
        signer.generate_signature(&mut signature),
        Err(MlDsaError::NotForSigning)
    );

    signer.init(&key(params)).unwrap();
    assert_eq!(
        signer.verify_signature(&signature),
        Err(MlDsaError::NotForVerification)
    );
    let mut short = vec![0; params.signature_length() - 1];
    assert_eq!(
        signer.generate_signature(&mut short),
        Err(MlDsaError::OutputTooShort)
    );
    assert_eq!(
        signer.set_context(&[0; 256]),
        Err(MlDsaError::ContextTooLong)
    );
}

#[test]
fn reset_discards_the_message() {
    let params = MlDsaParameters::ML_DSA_44;
    let private_key = key(params);
    let mut signer = MlDsaSigner::deterministic(params);
    signer.init(&private_key).unwrap();
    let expected = sign(&mut signer, MESSAGE);

    signer.update(b"discarded").unwrap();
    signer.reset();
    assert_eq!(sign(&mut signer, MESSAGE), expected);
}

#[test]
fn key_encodings_of_the_wrong_length_are_refused() {
    let params = MlDsaParameters::ML_DSA_44;
    let encoding = key(params).encoding();
    assert!(matches!(
        MlDsaPrivateKey::from_encoding(params, &encoding[1..]),
        Err(MlDsaError::InvalidKeyLength)
    ));
    let public = key(params).public_key().encoding();
    assert!(matches!(
        tc_ml_dsa::MlDsaPublicKey::from_encoding(params, &public[1..]),
        Err(MlDsaError::InvalidKeyLength)
    ));
}
