//! `ElGamalEngine`：加解密來回、區塊大小、密文檢查與錯誤，以及套上 PKCS#1。

mod common;

use common::{big, group14};
use std::sync::OnceLock;
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
    KeyPairGeneratorInit,
};
use tc_asym_encoding::Pkcs1Encoding;
use tc_bigint::{BigUint, PaddedBigUint};
use tc_elgamal::{
    ElGamalEngine, ElGamalError, ElGamalKeyGenerationParams, ElGamalKeyPairGenerator,
    ElGamalPrivateKey, ElGamalPublicKey,
};

/// 共用一組 2048 位元金鑰對，只產生一次。
fn keys() -> &'static (ElGamalPublicKey, ElGamalPrivateKey) {
    static KEYS: OnceLock<(ElGamalPublicKey, ElGamalPrivateKey)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rand::rng();
        let mut generator = ElGamalKeyPairGenerator::new();
        generator
            .init(ElGamalKeyGenerationParams::new(group14(), &mut rng))
            .unwrap();
        generator.generate_key_pair().unwrap()
    })
}

fn encryptor() -> ElGamalEngine<rand::rngs::ThreadRng> {
    let mut engine = ElGamalEngine::new(rand::rng());
    engine.init(CipherDirection::Encrypt, &keys().0).unwrap();
    engine
}

fn decryptor() -> ElGamalEngine<rand::rngs::ThreadRng> {
    let mut engine = ElGamalEngine::new(rand::rng());
    engine.init(CipherDirection::Decrypt, &keys().1).unwrap();
    engine
}

fn encrypt(message: &[u8]) -> Vec<u8> {
    let mut engine = encryptor();
    let mut ciphertext = vec![0; engine.output_block_size()];
    let length = engine.process_block(message, &mut ciphertext).unwrap();
    ciphertext.truncate(length);
    ciphertext
}

fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, ElGamalError> {
    let mut engine = decryptor();
    let mut plaintext = vec![0; engine.output_block_size()];
    let length = engine.process_block(ciphertext, &mut plaintext)?;
    plaintext.truncate(length);
    Ok(plaintext)
}

#[test]
fn the_block_sizes_follow_the_bit_length_of_p() {
    let (encryptor, decryptor) = (encryptor(), decryptor());
    assert_eq!(encryptor.input_block_size(), 255);
    assert_eq!(encryptor.output_block_size(), 512);
    assert_eq!(decryptor.input_block_size(), 512);
    assert_eq!(decryptor.output_block_size(), 256);
    let uninitialized = ElGamalEngine::new(rand::rng());
    assert_eq!(uninitialized.input_block_size(), 0);
    assert_eq!(uninitialized.output_block_size(), 0);
}

#[test]
fn decryption_recovers_every_message_length_left_padded_with_zeros() {
    for length in [1, 2, 31, 128, 254, 255] {
        let message: Vec<u8> = (0..length).map(|i| (i as u8) | 1).collect();
        let ciphertext = encrypt(&message);
        assert_eq!(ciphertext.len(), 512);
        let plaintext = decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.len(), 256);
        assert!(plaintext[..256 - length].iter().all(|&b| b == 0));
        assert_eq!(&plaintext[256 - length..], &message[..], "{length} bytes");
    }
}

#[test]
fn a_zero_message_is_rejected_since_its_ciphertext_could_not_be_decrypted() {
    let mut engine = encryptor();
    let mut output = vec![0; 512];
    for message in [&[][..], &[0; 5][..]] {
        assert_eq!(
            engine.process_block(message, &mut output),
            Err(ElGamalError::InputTooSmall)
        );
    }
}

#[test]
fn each_encryption_draws_a_fresh_k() {
    assert_ne!(encrypt(b"same"), encrypt(b"same"));
}

#[test]
fn a_message_longer_than_the_input_block_is_rejected() {
    let mut engine = encryptor();
    let mut output = vec![0; 512];
    assert_eq!(
        engine.process_block(&[1; 256], &mut output),
        Err(ElGamalError::InputTooLarge)
    );
}

#[test]
fn a_short_output_buffer_is_rejected_in_both_directions() {
    let ciphertext = encrypt(b"short");
    assert_eq!(
        encryptor().process_block(b"short", &mut [0; 511]),
        Err(ElGamalError::OutputTooShort)
    );
    assert_eq!(
        decryptor().process_block(&ciphertext, &mut [0; 255]),
        Err(ElGamalError::OutputTooShort)
    );
}

#[test]
fn a_ciphertext_of_the_wrong_length_is_rejected() {
    let ciphertext = encrypt(b"length");
    for length in [0, 511, 513] {
        let mut input = ciphertext.clone();
        input.resize(length, 0);
        assert_eq!(
            decrypt(&input),
            Err(ElGamalError::InvalidCiphertextLength),
            "{length} bytes"
        );
    }
}

#[test]
fn weak_ciphertext_elements_are_rejected() {
    let ciphertext = encrypt(b"weak");
    let p = big(keys().1.params().p());
    let p_less_one = (&p - 1u32).to_be_bytes_padded();
    for (index, weak) in [[0u8; 256].to_vec(), one(), p_less_one.clone()]
        .iter()
        .enumerate()
    {
        let mut gamma_weak = ciphertext.clone();
        gamma_weak[..256].copy_from_slice(weak);
        assert_eq!(
            decrypt(&gamma_weak),
            Err(ElGamalError::WeakCiphertext),
            "γ {index}"
        );
        let mut phi_weak = ciphertext.clone();
        phi_weak[256..].copy_from_slice(weak);
        assert_eq!(
            decrypt(&phi_weak),
            Err(ElGamalError::WeakCiphertext),
            "φ {index}"
        );
    }
}

#[test]
fn keys_must_match_the_direction() {
    let mut engine = ElGamalEngine::new(rand::rng());
    assert_eq!(
        engine.init(CipherDirection::Decrypt, &keys().0),
        Err(ElGamalError::WrongKeyForDirection)
    );
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &keys().1),
        Err(ElGamalError::WrongKeyForDirection)
    );
    assert_eq!(
        engine.process_block(b"x", &mut [0; 512]),
        Err(ElGamalError::NotInitialized)
    );
}

#[test]
fn weak_keys_are_rejected_at_init() {
    let params = group14();
    let p = big(params.p());
    let mut engine = ElGamalEngine::new(rand::rng());
    for y in [BigUint::from(1u8), &p - 1u32] {
        let key = ElGamalPublicKey::new(PaddedBigUint::from(y), params.clone());
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &key),
            Err(ElGamalError::InvalidKey)
        );
    }
    let key = ElGamalPrivateKey::new(PaddedBigUint::from(&p - 1u32), params);
    assert_eq!(
        engine.init(CipherDirection::Decrypt, &key),
        Err(ElGamalError::InvalidKey)
    );
}

#[test]
fn pkcs1_padding_round_trips_over_the_engine() {
    let message = b"padded by PKCS#1 v1.5";
    let mut encoding = Pkcs1Encoding::from_parts(ElGamalEngine::new(rand::rng()), rand::rng());
    encoding.init(CipherDirection::Encrypt, &keys().0).unwrap();
    let mut ciphertext = vec![0; encoding.output_block_size()];
    let length = encoding.process_block(message, &mut ciphertext).unwrap();

    let mut decoding = Pkcs1Encoding::from_parts(ElGamalEngine::new(rand::rng()), rand::rng());
    decoding.init(CipherDirection::Decrypt, &keys().1).unwrap();
    let mut plaintext = vec![0; decoding.output_block_size()];
    let written = decoding
        .process_block(&ciphertext[..length], &mut plaintext)
        .unwrap();
    assert_eq!(&plaintext[..written], message);
}

#[test]
fn the_engine_names_itself_as_bouncy_castle_does() {
    assert_eq!(ElGamalEngine::new(()).to_string(), "ElGamal");
}

fn one() -> Vec<u8> {
    let mut bytes = vec![0u8; 256];
    bytes[255] = 1;
    bytes
}

trait PaddedBytes {
    fn to_be_bytes_padded(&self) -> Vec<u8>;
}

impl PaddedBytes for BigUint {
    fn to_be_bytes_padded(&self) -> Vec<u8> {
        let bytes = tc_bigint::ArrayEncoding::<u8>::to_be(self);
        let mut padded = vec![0u8; 256];
        padded[256 - bytes.len()..].copy_from_slice(&bytes);
        padded
    }
}
