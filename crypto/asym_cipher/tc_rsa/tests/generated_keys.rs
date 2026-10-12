//! The keys of each generator run on the engines of the other: those of
//! this crate through RustCrypto, and those of RustCrypto through the
//! engines of this crate.

#![cfg(feature = "rustcrypto")]

use rand::SeedableRng;
use rand::rngs::StdRng;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BoxedUint, RsaPrivateKey, RsaPublicKey};
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
    KeyPairGeneratorInit,
};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_rsa_v2::{
    PaddedRsaCoreEngine, PaddedRsaCrtCoreEngine, RsaCoreEngineRustCrypto,
    RsaCrtCoreEngineRustCrypto, RsaKeyGenerationParamsOwned, RsaKeyOwned, RsaKeyPairGenerator,
    RsaKeyPairGeneratorRustCrypto, RsaKeyParams, RsaKeyRustCrypto, RsaPrivateCrtKeyOwned,
    RsaPrivateCrtKeyParams, RsaPrivateCrtKeyRustCrypto,
};

const BLOCK: [u8; 127] = [0x3c; 127];

fn params(seed: u64) -> RsaKeyGenerationParamsOwned {
    RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(seed)).with_strength(1024)
}

fn run(
    engine: &mut impl AsymmetricBlockCipher<Error = tc_rsa_v2::RsaError>,
    input: &[u8],
) -> [u8; 128] {
    let mut output = [0; 128];
    engine.process_block(input, &mut output).unwrap();
    output
}

fn boxed(value: &PaddedBigUint) -> BoxedUint {
    BoxedUint::from_be_slice_vartime(&value.to_be())
}

fn padded(value: &BoxedUint) -> PaddedBigUint {
    PaddedBigUint::from_be(&value.to_be_bytes()).unwrap()
}

#[test]
fn a_key_of_this_crate_runs_through_rustcrypto() {
    let mut generator = RsaKeyPairGenerator::<PaddedBigUint>::new();
    generator.init(params(1)).unwrap();
    let (public, private) = generator.generate_key_pair().unwrap();

    let mut encrypt = PaddedRsaCoreEngine::new();
    encrypt.init(CipherDirection::Encrypt, &public).unwrap();
    let ciphertext = run(&mut encrypt, &BLOCK);

    let theirs = RsaPrivateKey::from_components(
        boxed(private.modulus()),
        boxed(private.public_exponent()),
        boxed(private.exponent()),
        vec![boxed(private.p()), boxed(private.q())],
    )
    .unwrap();
    let mut decrypt = RsaCrtCoreEngineRustCrypto::new();
    decrypt
        .init(
            CipherDirection::Decrypt,
            &RsaPrivateCrtKeyRustCrypto::new(theirs).unwrap(),
        )
        .unwrap();
    assert_eq!(&run(&mut decrypt, &ciphertext)[1..], &BLOCK[..]);
}

#[test]
fn a_key_of_rustcrypto_runs_through_the_engines_of_this_crate() {
    let mut generator = RsaKeyPairGeneratorRustCrypto::new();
    generator.init(params(2)).unwrap();
    let (public, private) = generator.generate_key_pair().unwrap();

    let mut encrypt = RsaCoreEngineRustCrypto::new();
    encrypt.init(CipherDirection::Encrypt, &public).unwrap();
    let ciphertext = run(&mut encrypt, &BLOCK);

    let ours = RsaPrivateCrtKeyOwned::new(
        padded(private.modulus()),
        padded(private.public_exponent()),
        padded(private.exponent()),
        padded(private.p()),
        padded(private.q()),
        padded(private.dp()),
        padded(private.dq()),
        padded(private.q_inv()),
    );
    let mut decrypt = PaddedRsaCrtCoreEngine::new();
    decrypt.init(CipherDirection::Decrypt, &ours).unwrap();
    assert_eq!(&run(&mut decrypt, &ciphertext)[1..], &BLOCK[..]);

    let ours_public = RsaKeyOwned::new(false, padded(public.modulus()), padded(public.exponent()));
    let mut ours_encrypt = PaddedRsaCoreEngine::new();
    ours_encrypt
        .init(CipherDirection::Encrypt, &ours_public)
        .unwrap();
    assert_eq!(run(&mut ours_encrypt, &BLOCK), ciphertext);
}

#[test]
fn the_rustcrypto_wrappers_hand_out_what_rsa_holds() {
    let key = RsaPrivateKey::new(&mut StdRng::seed_from_u64(3), 1024).unwrap();
    let public = RsaKeyRustCrypto::new(
        RsaPublicKey::new(key.n().as_ref().clone(), key.e().clone()).unwrap(),
    );
    let private = RsaPrivateCrtKeyRustCrypto::new(key.clone()).unwrap();
    assert_eq!(public.modulus(), private.modulus());
    assert_eq!(private.exponent(), key.d());
}
