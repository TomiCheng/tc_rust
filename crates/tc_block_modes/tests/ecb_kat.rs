//! Tests for ECB mode.
//!
//! The AES vectors are the FIPS-197 appendix C examples. The defining property
//! of ECB — that it is exactly the underlying cipher, block by block — is
//! checked directly against a bare engine.

use tc_block_cipher::{AES_BLOCK_BYTES, AesEngine, AesParams, BlockCipherError};
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_block_modes::EcbBlockCipher;

/// Parses a hex string into bytes.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const PLAINTEXT: &str = "00112233445566778899aabbccddeeff";
const KEY128: &str = "000102030405060708090a0b0c0d0e0f";
const KEY256: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn ecb_encrypt(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut mode = EcbBlockCipher::new(AesEngine::new());
    mode.init(CipherDirection::Encrypt, &AesParams::new(key).unwrap())
        .unwrap();
    let mut out = vec![0u8; input.len()];
    let n = mode.process_block(input, &mut out).unwrap();
    assert_eq!(n, AES_BLOCK_BYTES);
    out
}

#[test]
fn fips197_aes128() {
    assert_eq!(
        ecb_encrypt(&hex(KEY128), &hex(PLAINTEXT)),
        hex("69c4e0d86a7b0430d8cdb78070b4c55a")
    );
}

#[test]
fn fips197_aes256() {
    assert_eq!(
        ecb_encrypt(&hex(KEY256), &hex(PLAINTEXT)),
        hex("8ea2b7ca516745bfeafc49904b496089")
    );
}

#[test]
fn matches_the_bare_engine() {
    // ECB 的定義：逐塊套用底層 cipher，輸出應與裸 engine 完全相同。
    let key = AesParams::new(&hex(KEY128)).unwrap();
    let input = hex(PLAINTEXT);

    let mut bare = AesEngine::new();
    bare.init(CipherDirection::Encrypt, &key).unwrap();
    let mut bare_out = [0u8; AES_BLOCK_BYTES];
    bare.process_block(&input, &mut bare_out).unwrap();

    let mut mode = EcbBlockCipher::new(AesEngine::new());
    mode.init(CipherDirection::Encrypt, &key).unwrap();
    let mut mode_out = [0u8; AES_BLOCK_BYTES];
    mode.process_block(&input, &mut mode_out).unwrap();

    assert_eq!(mode_out, bare_out);
}

#[test]
fn decrypt_round_trips() {
    let key = AesParams::new(&hex(KEY128)).unwrap();
    let plaintext = hex(PLAINTEXT);

    let mut mode = EcbBlockCipher::new(AesEngine::new());
    mode.init(CipherDirection::Encrypt, &key).unwrap();
    let mut ct = [0u8; AES_BLOCK_BYTES];
    mode.process_block(&plaintext, &mut ct).unwrap();

    mode.init(CipherDirection::Decrypt, &key).unwrap();
    let mut pt = [0u8; AES_BLOCK_BYTES];
    mode.process_block(&ct, &mut pt).unwrap();

    assert_eq!(pt.to_vec(), plaintext);
}

#[test]
fn reports_composed_algorithm_name_and_block_size() {
    let mode = EcbBlockCipher::new(AesEngine::new());
    assert_eq!(mode.algorithm_name(), "AES/ECB");
    assert_eq!(mode.block_size(), AES_BLOCK_BYTES);
}

#[test]
fn repeated_blocks_encrypt_identically() {
    let key = AesParams::new(&hex(KEY128)).unwrap();
    let input = hex(PLAINTEXT);

    let mut mode = EcbBlockCipher::new(AesEngine::new());
    mode.init(CipherDirection::Encrypt, &key).unwrap();
    let mut first = [0u8; AES_BLOCK_BYTES];
    mode.process_block(&input, &mut first).unwrap();

    // ECB 無鏈結狀態：同一塊明文永遠得到同一塊密文（這也是 ECB 的弱點）。
    let mut second = [0u8; AES_BLOCK_BYTES];
    mode.process_block(&input, &mut second).unwrap();

    assert_eq!(first, second);
}

#[test]
fn stays_interchangeable_with_a_bare_engine_behind_dyn() {
    // Error = E::Error，故 mode 與 engine 能放進同一個 trait object 型別。
    let key = AesParams::new(&hex(KEY128)).unwrap();

    let mut engine = AesEngine::new();
    engine.init(CipherDirection::Encrypt, &key).unwrap();
    let mut mode = EcbBlockCipher::new(AesEngine::new());
    mode.init(CipherDirection::Encrypt, &key).unwrap();

    let ciphers: Vec<Box<dyn BlockCipher<Error = BlockCipherError>>> =
        vec![Box::new(engine), Box::new(mode)];

    let input = hex(PLAINTEXT);
    for mut cipher in ciphers {
        let mut out = [0u8; AES_BLOCK_BYTES];
        cipher.process_block(&input, &mut out).unwrap();
        assert_eq!(out.to_vec(), hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }
}
