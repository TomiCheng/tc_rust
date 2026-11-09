use tc_signer::{Signer, SignerInit};
use tc_slh_dsa::{HashSlhDsaSigner, SlhDsaError, SlhDsaParameters, SlhDsaPrivateKey, SlhDsaSigner};

const MESSAGE: &[u8] = b"attack at dawn";

fn key(params: SlhDsaParameters) -> SlhDsaPrivateKey {
    let n = params.n();
    SlhDsaPrivateKey::from_seeds(params, &vec![1; n], &vec![2; n], &vec![3; n]).unwrap()
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
fn hedged_signatures_differ_and_verify() {
    for params in [SlhDsaParameters::SHA2_128F, SlhDsaParameters::SHAKE_128F] {
        let private_key = key(params);
        let mut signer = SlhDsaSigner::new(params, rand::rng());
        signer.init(&private_key).unwrap();
        let first = sign(&mut signer, MESSAGE);
        let second = sign(&mut signer, MESSAGE);
        assert_ne!(first, second);
        assert_eq!(first.len(), params.signature_length());

        let mut verifier = SlhDsaSigner::deterministic(params);
        verifier.init(&private_key.public_key()).unwrap();
        assert!(verify(&mut verifier, MESSAGE, &first));
        assert!(verify(&mut verifier, MESSAGE, &second));
    }
}

#[test]
fn a_changed_message_context_or_signature_does_not_verify() {
    let params = SlhDsaParameters::SHAKE_128F;
    let private_key = key(params);
    let mut signer = SlhDsaSigner::deterministic(params);
    signer.init(&private_key).unwrap();
    let signature = sign(&mut signer, MESSAGE);

    let mut verifier = SlhDsaSigner::deterministic(params);
    verifier.init(&private_key.public_key()).unwrap();
    assert!(!verify(&mut verifier, b"attack at dusk", &signature));
    let mut tampered = signature.clone();
    tampered[1000] ^= 1;
    assert!(!verify(&mut verifier, MESSAGE, &tampered));
    assert!(!verify(&mut verifier, MESSAGE, &signature[1..]));

    let mut other = SlhDsaSigner::deterministic(params);
    other.set_context(b"other").unwrap();
    other.init(&private_key.public_key()).unwrap();
    assert!(!verify(&mut other, MESSAGE, &signature));
}

#[test]
fn hash_slh_dsa_verifies_and_differs_from_pure_slh_dsa() {
    for (params, name) in [
        (SlhDsaParameters::SHA2_128F, "SLH-DSA-SHA2-128f-WITH-SHA256"),
        (
            SlhDsaParameters::SHAKE_128F,
            "SLH-DSA-SHAKE-128f-WITH-SHAKE128",
        ),
        (SlhDsaParameters::SHA2_192F, "SLH-DSA-SHA2-192f-WITH-SHA512"),
        (
            SlhDsaParameters::SHAKE_192F,
            "SLH-DSA-SHAKE-192f-WITH-SHAKE256",
        ),
    ] {
        let private_key = key(params);
        let mut signer = HashSlhDsaSigner::deterministic(params);
        assert_eq!(signer.name(), name);
        signer.init(&private_key).unwrap();
        let signature = sign(&mut signer, MESSAGE);

        let mut verifier = HashSlhDsaSigner::deterministic(params);
        verifier.init(&private_key.public_key()).unwrap();
        assert!(verify(&mut verifier, MESSAGE, &signature));
        assert!(!verify(&mut verifier, b"attack at dusk", &signature));

        let mut pure = SlhDsaSigner::deterministic(params);
        pure.init(&private_key.public_key()).unwrap();
        assert!(!verify(&mut pure, MESSAGE, &signature));
    }
}

#[test]
fn the_signer_refuses_the_wrong_key_parameters_or_use() {
    let params = SlhDsaParameters::SHAKE_128F;
    let mut signer = SlhDsaSigner::deterministic(params);
    assert_eq!(signer.update(MESSAGE), Err(SlhDsaError::NotInitialized));
    assert_eq!(
        signer.init(&key(SlhDsaParameters::SHA2_128F)),
        Err(SlhDsaError::ParameterMismatch)
    );

    signer.init(&key(params).public_key()).unwrap();
    let mut signature = vec![0; params.signature_length()];
    assert_eq!(
        signer.generate_signature(&mut signature),
        Err(SlhDsaError::NotForSigning)
    );

    signer.init(&key(params)).unwrap();
    assert_eq!(
        signer.verify_signature(&signature),
        Err(SlhDsaError::NotForVerification)
    );
    let mut short = vec![0; params.signature_length() - 1];
    assert_eq!(
        signer.generate_signature(&mut short),
        Err(SlhDsaError::OutputTooShort)
    );
    assert_eq!(
        signer.set_context(&[0; 256]),
        Err(SlhDsaError::ContextTooLong)
    );
}

#[test]
fn reset_discards_the_message() {
    let params = SlhDsaParameters::SHAKE_128F;
    let mut signer = SlhDsaSigner::deterministic(params);
    signer.init(&key(params)).unwrap();
    let expected = sign(&mut signer, MESSAGE);
    signer.update(b"discarded").unwrap();
    signer.reset();
    assert_eq!(sign(&mut signer, MESSAGE), expected);
}

#[test]
fn keys_round_trip_through_their_encodings_and_refuse_the_wrong_length() {
    let params = SlhDsaParameters::SHA2_128F;
    let private_key = key(params);
    let encoding = private_key.encoding();
    assert_eq!(encoding.len(), params.private_key_length());
    let decoded = SlhDsaPrivateKey::from_encoding(params, &encoding).unwrap();
    assert_eq!(decoded.public_key(), private_key.public_key());
    assert!(matches!(
        SlhDsaPrivateKey::from_encoding(params, &encoding[1..]),
        Err(SlhDsaError::InvalidKeyLength)
    ));
    assert!(matches!(
        SlhDsaPrivateKey::from_seeds(params, &[0; 15], &[0; 16], &[0; 16]),
        Err(SlhDsaError::InvalidKeyLength)
    ));
}
