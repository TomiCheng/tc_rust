//! `NaccacheSternEngine`：Bouncy Castle `NaccacheSternTest` 的論文玩具例子、同態加法、
//! 區塊大小與錯誤。

use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
use tc_modular::{ModPow, NonZero};
use tc_naccache_stern::{
    NaccacheSternEngine, NaccacheSternError, NaccacheSternPrivateKey, NaccacheSternPublicKey,
};

// 論文的例子，同 BC：a = 101，u = 3·5·7；b = 191，v = 11·13·17；g = 131。
const P: u64 = 2 * 101 * 3 * 5 * 7 + 1;
const Q: u64 = 2 * 191 * 11 * 13 * 17 + 1;
const SIGMA: u64 = 3 * 5 * 7 * 11 * 13 * 17;
const SIGMA_BITS: u32 = 18;

fn keys() -> (NaccacheSternPublicKey, NaccacheSternPrivateKey) {
    let n = PaddedBigUint::from(P * Q);
    let g = PaddedBigUint::from(131u8);
    (
        NaccacheSternPublicKey::new(g.clone(), n.clone(), SIGMA_BITS),
        NaccacheSternPrivateKey::new(
            g,
            n,
            SIGMA_BITS,
            vec![3, 5, 7, 11, 13, 17],
            PaddedBigUint::from((P - 1) * (Q - 1)),
        ),
    )
}

fn encrypt(m: u64) -> Vec<u8> {
    let mut engine = NaccacheSternEngine::new();
    engine.init(CipherDirection::Encrypt, &keys().0).unwrap();
    let mut ciphertext = vec![0; engine.output_block_size()];
    let message = (m as u16).to_be_bytes();
    let length = engine.process_block(&message, &mut ciphertext).unwrap();
    ciphertext.truncate(length);
    ciphertext
}

fn decrypt(ciphertext: &[u8]) -> Result<u64, NaccacheSternError> {
    let mut engine = NaccacheSternEngine::new();
    engine.init(CipherDirection::Decrypt, &keys().1).unwrap();
    let mut plaintext = vec![0; engine.output_block_size()];
    let length = engine.process_block(ciphertext, &mut plaintext)?;
    Ok(plaintext[..length]
        .iter()
        .fold(0, |m, &byte| m << 8 | u64::from(byte)))
}

#[test]
fn the_paper_example_encrypts_to_g_to_the_m_and_decrypts_back() {
    let ciphertext = encrypt(202);
    let n = NonZero::new(BigUint::from(P * Q)).unwrap();
    let expected = BigUint::from(131u8).mod_pow(&BigUint::from(202u8), &n);
    assert_eq!(
        BigUint::from_be(&ciphertext).unwrap(),
        expected,
        "c = g^m mod n"
    );
    assert_eq!(decrypt(&ciphertext), Ok(202));
}

#[test]
fn every_tested_message_below_the_input_bound_round_trips() {
    for m in (0..65_536u64).step_by(997).chain([1, 2, 65_535]) {
        assert_eq!(decrypt(&encrypt(m)), Ok(m), "m = {m}");
    }
}

#[test]
fn multiplying_ciphertexts_adds_the_messages_modulo_sigma() {
    let mut engine = NaccacheSternEngine::new();
    engine.init(CipherDirection::Encrypt, &keys().0).unwrap();
    let mut sum = vec![0; engine.output_block_size()];
    engine
        .add_crypted_blocks(&encrypt(1_000), &encrypt(2_345), &mut sum)
        .unwrap();
    assert_eq!(decrypt(&sum), Ok(3_345));

    // 65535 加四次是 262140，超過 σ = 255255，會繞回。
    let block = encrypt(65_535);
    let mut total = block.clone();
    for _ in 0..3 {
        let mut next = vec![0; total.len()];
        engine
            .add_crypted_blocks(&total, &block, &mut next)
            .unwrap();
        total = next;
    }
    assert_eq!(decrypt(&total), Ok(4 * 65_535 % SIGMA));
}

#[test]
fn the_block_sizes_follow_n_and_sigma() {
    let (public_key, private_key) = keys();
    let n_bytes = (64 - (P * Q).leading_zeros()) as usize / 8 + 1;
    let mut encryptor = NaccacheSternEngine::new();
    assert_eq!(encryptor.input_block_size(), 0);
    encryptor
        .init(CipherDirection::Encrypt, &public_key)
        .unwrap();
    assert_eq!(encryptor.input_block_size(), 2);
    assert_eq!(encryptor.output_block_size(), n_bytes);
    let mut decryptor = NaccacheSternEngine::new();
    decryptor
        .init(CipherDirection::Decrypt, &private_key)
        .unwrap();
    assert_eq!(decryptor.input_block_size(), n_bytes);
    assert_eq!(decryptor.output_block_size(), 3);
    assert_eq!(encryptor.to_string(), "NaccacheStern");
}

#[test]
fn errors_are_reported() {
    let (public_key, _) = keys();
    let mut engine = NaccacheSternEngine::new();
    assert_eq!(
        engine.process_block(&[1], &mut [0; 16]),
        Err(NaccacheSternError::NotInitialized)
    );
    assert_eq!(
        engine.init(CipherDirection::Decrypt, &public_key),
        Err(NaccacheSternError::WrongKeyForDirection)
    );

    engine.init(CipherDirection::Encrypt, &public_key).unwrap();
    assert_eq!(
        engine.process_block(&[1, 2, 3], &mut [0; 16]),
        Err(NaccacheSternError::InputTooLarge)
    );
    assert_eq!(
        engine.process_block(&[1], &mut [0; 2]),
        Err(NaccacheSternError::OutputTooShort)
    );

    let ciphertext = encrypt(7);
    assert_eq!(
        decrypt(&ciphertext[1..]),
        Err(NaccacheSternError::InvalidCiphertextLength)
    );
    // 0 不是模 n 的可逆元，c^(φ/pᵢ) 不在任何表裡。
    assert_eq!(
        decrypt(&vec![0; ciphertext.len()]),
        Err(NaccacheSternError::LookupFailed)
    );
}

#[test]
fn invalid_keys_are_rejected_at_init() {
    let g = PaddedBigUint::from(131u8);
    let even = NaccacheSternPublicKey::new(g.clone(), PaddedBigUint::from(P * Q + 1), 18);
    assert_eq!(
        NaccacheSternEngine::new().init(CipherDirection::Encrypt, &even),
        Err(NaccacheSternError::InvalidKey)
    );
    // 19 不整除 φ(n)。
    let wrong_primes = NaccacheSternPrivateKey::new(
        g,
        PaddedBigUint::from(P * Q),
        18,
        vec![3, 5, 7, 11, 13, 19],
        PaddedBigUint::from((P - 1) * (Q - 1)),
    );
    assert_eq!(
        NaccacheSternEngine::new().init(CipherDirection::Decrypt, &wrong_primes),
        Err(NaccacheSternError::InvalidKey)
    );
}
