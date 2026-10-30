//! `ElGamalKeyPairGenerator` 與 `ElGamalParametersGenerator`：借用 DH 的產生器。

mod common;

use common::{big, group14};
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
    KeyPairGenerator, KeyPairGeneratorInit,
};
use tc_bigint::{BigUint, PaddedBigUint};
use tc_dh_key::DhError;
use tc_elgamal::{
    ElGamalEngine, ElGamalError, ElGamalKeyGenerationParams, ElGamalKeyPairGenerator,
    ElGamalParameters, ElGamalParametersGenerator,
};
use tc_modular::{ModPow, NonZero};

#[test]
fn the_public_value_is_g_to_a_private_value_in_two_to_p_minus_two() {
    let params = group14();
    let mut rng = rand::rng();
    let mut generator = ElGamalKeyPairGenerator::new();
    generator
        .init(ElGamalKeyGenerationParams::new(params.clone(), &mut rng))
        .unwrap();
    let p = big(params.p());
    let modulus = NonZero::new(p.clone()).unwrap();
    for _ in 0..3 {
        let (public_key, private_key) = generator.generate_key_pair().unwrap();
        let x = big(private_key.x());
        assert!(x >= BigUint::from(2u8) && x <= &p - 2u32);
        assert_eq!(
            big(public_key.y()),
            BigUint::from(2u8).mod_pow(&x, &modulus)
        );
        assert_eq!(public_key.params(), &params);
        assert!(!public_key.is_private_key());
        assert!(private_key.is_private_key());
    }
}

#[test]
fn a_set_length_gives_private_values_of_exactly_that_many_bits() {
    let mut rng = rand::rng();
    let mut generator = ElGamalKeyPairGenerator::new();
    let params = group14().with_l(256);
    generator
        .init(ElGamalKeyGenerationParams::new(params, &mut rng))
        .unwrap();
    let (_, private_key) = generator.generate_key_pair().unwrap();
    assert_eq!(big(private_key.x()).bits(), 256);
}

#[test]
fn invalid_parameters_and_an_uninitialized_generator_are_errors() {
    let mut rng = rand::rng();
    let mut generator = ElGamalKeyPairGenerator::new();
    let params = ElGamalParameters::new(PaddedBigUint::from(24u8), PaddedBigUint::from(2u8));
    assert_eq!(
        generator.init(ElGamalKeyGenerationParams::new(params, &mut rng)),
        Err(ElGamalError::InvalidParameters(DhError::InvalidModulus))
    );
    assert_eq!(
        ElGamalKeyPairGenerator::new().generate_key_pair().err(),
        Some(ElGamalError::NotInitialized)
    );
}

#[test]
fn the_strength_is_l_or_the_bit_length_of_p() {
    let mut rng = rand::rng();
    assert_eq!(
        ElGamalKeyGenerationParams::new(group14(), &mut rng).strength(),
        2048
    );
    assert_eq!(
        ElGamalKeyGenerationParams::new(group14().with_l(300), &mut rng).strength(),
        300
    );
}

#[test]
fn generated_parameters_carry_a_round_trip() {
    let mut rng = rand::rng();
    let mut parameters_generator = ElGamalParametersGenerator::new();
    parameters_generator.init(192, 20, &mut rng).unwrap();
    let params = parameters_generator.generate_parameters().unwrap();
    assert_eq!(params.p().bits(), 192);
    assert_eq!(big(params.g()), BigUint::from(2u8));
    assert_eq!(params.l(), 0);

    let mut key_rng = rand::rng();
    let mut generator = ElGamalKeyPairGenerator::new();
    generator
        .init(ElGamalKeyGenerationParams::new(params, &mut key_rng))
        .unwrap();
    let (public_key, private_key) = generator.generate_key_pair().unwrap();

    let mut encryptor = ElGamalEngine::new(rand::rng());
    encryptor
        .init(CipherDirection::Encrypt, &public_key)
        .unwrap();
    let mut ciphertext = vec![0; encryptor.output_block_size()];
    encryptor.process_block(b"tiny", &mut ciphertext).unwrap();

    let mut decryptor = ElGamalEngine::new(rand::rng());
    decryptor
        .init(CipherDirection::Decrypt, &private_key)
        .unwrap();
    let mut plaintext = vec![0; decryptor.output_block_size()];
    let length = decryptor
        .process_block(&ciphertext, &mut plaintext)
        .unwrap();
    assert!(plaintext[..length].ends_with(b"tiny"));
}

#[test]
fn the_parameters_generator_checks_its_settings() {
    let mut rng = rand::rng();
    assert_eq!(
        ElGamalParametersGenerator::new().init(63, 20, &mut rng),
        Err(ElGamalError::InvalidParameters(DhError::InvalidSize))
    );
    assert_eq!(
        ElGamalParametersGenerator::new()
            .generate_parameters()
            .err(),
        Some(ElGamalError::InvalidParameters(DhError::NotInitialized))
    );
}
