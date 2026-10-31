//! `Gost3410Signer` 的錯誤與範圍檢查，以及經 `Gost3410DigestSigner` 的往返。

use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_dsa::{Dsa, DsaInit, Gost3410DigestSigner};
use tc_gost3410::{Gost3410Signer, Gost3410SignerError};
use tc_gost3410_key::{
    Gost3410Error, Gost3410KeyGenerationParams, Gost3410KeyPairGenerator, Gost3410Parameters,
    Gost3410ParametersGenerator, Gost3410PrivateKey, Gost3410PublicKey,
};
use tc_gost3411::Gost3411Digest;
use tc_signer::{Signer, SignerInit};

fn key_pair() -> (Gost3410PublicKey, Gost3410PrivateKey) {
    let mut rng = rand::rng();
    let mut generator = Gost3410ParametersGenerator::new();
    generator.init(512, 2, &mut rng).unwrap();
    let params = generator.generate_parameters().unwrap();
    let mut rng = rand::rng();
    let mut keys = Gost3410KeyPairGenerator::new();
    keys.init(Gost3410KeyGenerationParams::new(params, &mut rng))
        .unwrap();
    keys.generate_key_pair().unwrap()
}

#[test]
fn the_digest_signer_signs_and_verifies_and_rejects_other_messages() {
    let (public_key, private_key) = key_pair();
    let mut signer =
        Gost3410DigestSigner::new(Gost3410Signer::new(rand::rng()), Gost3411Digest::new());
    signer.init(&private_key).unwrap();
    signer.update(b"Message for sign").unwrap();
    let mut signature = vec![0; signer.max_signature_size()];
    let length = signer.generate_signature(&mut signature).unwrap();
    assert_eq!(length, 64);

    let mut verifier =
        Gost3410DigestSigner::new(Gost3410Signer::new(rand::rng()), Gost3411Digest::new());
    verifier.init(&public_key).unwrap();
    verifier.update(b"Message for sign").unwrap();
    assert!(verifier.verify_signature(&signature).unwrap());
    verifier.update(b"message for sign").unwrap();
    assert!(!verifier.verify_signature(&signature).unwrap());
}

#[test]
fn errors_are_reported() {
    let (public_key, private_key) = key_pair();
    let mut signer = Gost3410Signer::new(rand::rng());
    assert_eq!(
        signer.generate_signature(&[1]),
        Err(Gost3410SignerError::NotInitialized)
    );
    signer.init(&public_key).unwrap();
    assert_eq!(
        signer.generate_signature(&[1]),
        Err(Gost3410SignerError::NotForSigning)
    );
    // r 與 s 要在 [1, q − 1]。
    let one = PaddedBigUint::from(1u8);
    let q = private_key.params().q().clone();
    assert!(
        !signer
            .verify_signature(&[1], &PaddedBigUint::from(0u8), &one)
            .unwrap()
    );
    assert!(!signer.verify_signature(&[1], &one, &q).unwrap());

    signer.init(&private_key).unwrap();
    assert_eq!(
        signer.verify_signature(&[1], &one, &one),
        Err(Gost3410SignerError::NotForVerifying)
    );

    let params = Gost3410Parameters::new(
        PaddedBigUint::from(23u8),
        PaddedBigUint::from(11u8),
        PaddedBigUint::from(2u8),
    );
    assert_eq!(
        signer.init(&Gost3410PrivateKey::new(PaddedBigUint::from(11u8), params)),
        Err(Gost3410SignerError::InvalidKey(
            Gost3410Error::InvalidPrivateKey
        ))
    );
    assert_eq!(
        signer.generate_signature(&[1]),
        Err(Gost3410SignerError::NotInitialized)
    );
}
