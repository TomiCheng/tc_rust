//! Every engine of the crate runs the same key to the same blocks: the
//! fixed-width ones always, the padded ones with `alloc`, those of
//! RustCrypto with `rustcrypto`.

mod common;

use common::{BLOCK, D, DP, DQ, N, P, Q, Q_INV, bytes};
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, FixedBigUint, Word};
use tc_rsa_v2::{
    FixedRsaCoreEngine, FixedRsaCrtCoreEngine, RsaError, RsaKeyRef, RsaPrivateCrtKeyRef,
};

const WIDE: usize = 2048 / Word::BITS as usize;
const HALF: usize = 1024 / Word::BITS as usize;

type Engine = Box<dyn AsymmetricBlockCipher<Error = RsaError>>;

/// The output of `engine` on `input`, at the 256 bytes of the modulus.
fn run(engine: &mut Engine, input: &[u8]) -> Vec<u8> {
    let mut output = vec![0; engine.output_block_size()];
    let length = engine.process_block(input, &mut output).unwrap();
    output.truncate(length);
    output
}

/// The engines that encrypt with the public key, by name.
fn public_engines() -> Vec<(&'static str, Engine)> {
    let (n, e) = (bytes(N), [1, 0, 1]);
    let wide = |value: &[u8]| FixedBigUint::<WIDE>::from_be(value).unwrap();
    let (fixed_n, fixed_e) = (wide(&n), wide(&e));
    let mut fixed = FixedRsaCoreEngine::new();
    fixed
        .init(
            CipherDirection::Encrypt,
            &RsaKeyRef::new(false, &fixed_n, &fixed_e),
        )
        .unwrap();
    // Only the fixed-width engines, without `alloc`.
    #[cfg_attr(not(feature = "alloc"), allow(unused_mut))]
    let mut engines: Vec<(&str, Engine)> = vec![("fixed", Box::new(fixed))];

    #[cfg(feature = "alloc")]
    {
        use tc_bigint::PaddedBigUint;
        let padded = |value: &[u8]| PaddedBigUint::from_be(value).unwrap();
        let mut engine = tc_rsa_v2::PaddedRsaCoreEngine::new();
        engine
            .init(
                CipherDirection::Encrypt,
                &tc_rsa_v2::RsaKeyOwned::new(false, padded(&n), padded(&e)),
            )
            .unwrap();
        engines.push(("padded", Box::new(engine)));
    }

    #[cfg(feature = "rustcrypto")]
    {
        use rsa::{BoxedUint, RsaPublicKey};
        let boxed = BoxedUint::from_be_slice_vartime;
        let key = RsaPublicKey::new(boxed(&n), boxed(&e)).unwrap();
        let mut engine = tc_rsa_v2::RsaCoreEngineRustCrypto::new();
        engine
            .init(
                CipherDirection::Encrypt,
                &tc_rsa_v2::RsaKeyRustCrypto::new(key),
            )
            .unwrap();
        engines.push(("rustcrypto", Box::new(engine)));
    }
    engines
}

/// The engines that decrypt with the private key, by name: those of the
/// plain power of `d` and those of the CRT.
fn private_engines() -> Vec<(&'static str, Engine)> {
    let [n, e, d, p, q, dp, dq, q_inv] = [N, "010001", D, P, Q, DP, DQ, Q_INV].map(bytes);
    let wide = |value: &[u8]| FixedBigUint::<WIDE>::from_be(value).unwrap();
    let half = |value: &[u8]| FixedBigUint::<HALF>::from_be(value).unwrap();
    let (fixed_n, fixed_e, fixed_d) = (wide(&n), wide(&e), wide(&d));
    let [fixed_p, fixed_q, fixed_dp, fixed_dq, fixed_q_inv] =
        [&p, &q, &dp, &dq, &q_inv].map(|value| half(value));
    let mut plain = FixedRsaCoreEngine::new();
    plain
        .init(
            CipherDirection::Decrypt,
            &RsaKeyRef::new(true, &fixed_n, &fixed_d),
        )
        .unwrap();
    let mut crt = FixedRsaCrtCoreEngine::new();
    let key = RsaPrivateCrtKeyRef::new(
        &fixed_n,
        &fixed_e,
        &fixed_d,
        &fixed_p,
        &fixed_q,
        &fixed_dp,
        &fixed_dq,
        &fixed_q_inv,
    );
    crt.init(CipherDirection::Decrypt, &key).unwrap();
    // Only the fixed-width engines, without `alloc`.
    #[cfg_attr(not(feature = "alloc"), allow(unused_mut))]
    let mut engines: Vec<(&str, Engine)> =
        vec![("fixed", Box::new(plain)), ("fixed crt", Box::new(crt))];

    #[cfg(feature = "alloc")]
    {
        use tc_bigint::PaddedBigUint;
        use tc_rsa_v2::{
            PaddedRsaCoreEngine, PaddedRsaCrtCoreEngine, RsaKeyOwned, RsaPrivateCrtKeyOwned,
        };
        let padded = |value: &[u8]| PaddedBigUint::from_be(value).unwrap();
        let mut plain = PaddedRsaCoreEngine::new();
        plain
            .init(
                CipherDirection::Decrypt,
                &RsaKeyOwned::new(true, padded(&n), padded(&d)),
            )
            .unwrap();
        let mut crt = PaddedRsaCrtCoreEngine::new();
        let key = RsaPrivateCrtKeyOwned::new(
            padded(&n),
            padded(&e),
            padded(&d),
            padded(&p),
            padded(&q),
            padded(&dp),
            padded(&dq),
            padded(&q_inv),
        );
        crt.init(CipherDirection::Decrypt, &key).unwrap();
        engines.push(("padded", Box::new(plain)));
        engines.push(("padded crt", Box::new(crt)));
    }

    #[cfg(feature = "rustcrypto")]
    {
        use rsa::{BoxedUint, RsaPrivateKey};
        let boxed = BoxedUint::from_be_slice_vartime;
        let key = RsaPrivateKey::from_components(
            boxed(&n),
            boxed(&e),
            boxed(&d),
            vec![boxed(&p), boxed(&q)],
        )
        .unwrap();
        let mut crt = tc_rsa_v2::RsaCrtCoreEngineRustCrypto::new();
        crt.init(
            CipherDirection::Decrypt,
            &tc_rsa_v2::RsaPrivateCrtKeyRustCrypto::new(key).unwrap(),
        )
        .unwrap();
        engines.push(("rustcrypto crt", Box::new(crt)));
    }
    engines
}

#[test]
fn every_public_engine_encrypts_a_block_to_the_same_ciphertext() {
    let mut engines = public_engines();
    let (_, first) = &mut engines[0];
    let expected = run(first, &BLOCK);
    for (name, engine) in &mut engines[1..] {
        assert_eq!(run(engine, &BLOCK), expected, "{name}");
    }
}

#[test]
fn every_private_engine_decrypts_the_ciphertext_back_to_the_block() {
    let (_, mut encrypt) = public_engines().swap_remove(0);
    let ciphertext = run(&mut encrypt, &BLOCK);
    for (name, mut engine) in private_engines() {
        let plaintext = run(&mut engine, &ciphertext);
        assert_eq!(plaintext[0], 0, "{name}");
        assert_eq!(&plaintext[1..], &BLOCK[..], "{name}");
    }
}

#[test]
fn every_private_engine_signs_a_block_to_the_same_signature() {
    let mut engines: Vec<(&str, Engine)> = private_engines();
    let signatures: Vec<(&str, Vec<u8>)> = engines
        .iter_mut()
        .map(|(name, engine)| (*name, run(engine, &BLOCK)))
        .collect();
    for (name, signature) in &signatures[1..] {
        assert_eq!(signature, &signatures[0].1, "{name}");
    }
}
