//! Tests for the keystream modes: CFB, OFB, and CTR (SIC).
//!
//! All vectors are from NIST SP 800-38A — §F.3 for CFB, §F.4 for OFB, §F.5 for
//! CTR — using that document's shared AES-128 key and plaintext. Four blocks are
//! chained in each case so the feedback itself is exercised, and CFB8 covers a
//! segment smaller than the cipher's block.

use tc_block_cipher::{AES_BLOCK_BYTES, AesEngine, AesParams};
use tc_block_modes::{
    BlockCipherModeError, CfbBlockCipher, CfbParams, OfbBlockCipher, OfbParams, SicBlockCipher,
    SicParams,
};
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

/// Parses a hex string into bytes.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const IV: &str = "000102030405060708090a0b0c0d0e0f";
const CTR_IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);

/// Feeds `input` through `mode` one segment at a time.
fn run<M: BlockCipher>(mode: &mut M, input: &[u8]) -> Vec<u8> {
    let seg = mode.block_size();
    let mut out = vec![0u8; input.len()];
    for (chunk_in, chunk_out) in input.chunks(seg).zip(out.chunks_mut(seg)) {
        let n = mode.process_block(chunk_in, chunk_out).unwrap();
        assert_eq!(n, seg);
    }
    out
}

// ---- CFB ----

fn aes_cfb(bits: usize, direction: CipherDirection, input: &[u8]) -> Vec<u8> {
    let key = hex(KEY);
    let iv = hex(IV);
    let mut mode = CfbBlockCipher::new(AesEngine::new(), bits).unwrap();
    mode.init(
        direction,
        &CfbParams::with_iv(AesParams::new(&key).unwrap(), &iv),
    )
    .unwrap();
    run(&mut mode, input)
}

const CFB128_CIPHERTEXT: &str = concat!(
    "3b3fd92eb72dad20333449f8e83cfb4a",
    "c8a64537a0b3a93fcde3cdad9f1ce58b",
    "26751f67a3cbb140b1808cf187a4f4df",
    "c04b05357c5d1c0eeac4c66f9ff7f2e6",
);

#[test]
fn nist_cfb128_encrypt() {
    assert_eq!(
        aes_cfb(128, CipherDirection::Encrypt, &hex(PLAINTEXT)),
        hex(CFB128_CIPHERTEXT)
    );
}

#[test]
fn nist_cfb128_decrypt() {
    assert_eq!(
        aes_cfb(128, CipherDirection::Decrypt, &hex(CFB128_CIPHERTEXT)),
        hex(PLAINTEXT)
    );
}

#[test]
fn nist_cfb8_uses_a_one_byte_segment() {
    let mut mode = CfbBlockCipher::new(AesEngine::new(), 8).unwrap();
    // 段大小即 process_block 一次處理的量，並非底層分組大小。
    assert_eq!(mode.block_size(), 1);
    assert_eq!(mode.algorithm_name(), "AES/CFB8");

    let key = hex(KEY);
    let iv = hex(IV);
    mode.init(
        CipherDirection::Encrypt,
        &CfbParams::with_iv(AesParams::new(&key).unwrap(), &iv),
    )
    .unwrap();
    let ct = run(&mut mode, &hex("6bc1bee22e409f96"));
    assert_eq!(ct, hex("3b79424c9c0dd436"));
}

#[test]
fn cfb_rejects_a_feedback_size_that_is_not_whole_bytes() {
    assert!(matches!(
        CfbBlockCipher::new(AesEngine::new(), 12),
        Err(BlockCipherModeError::InvalidFeedbackSize(12))
    ));
    assert!(matches!(
        CfbBlockCipher::new(AesEngine::new(), 0),
        Err(BlockCipherModeError::InvalidFeedbackSize(0))
    ));
    // 超過底層分組大小。
    assert!(matches!(
        CfbBlockCipher::new(AesEngine::new(), 256),
        Err(BlockCipherModeError::InvalidFeedbackSize(256))
    ));
}

// ---- OFB ----

const OFB128_CIPHERTEXT: &str = concat!(
    "3b3fd92eb72dad20333449f8e83cfb4a",
    "7789508d16918f03f53c52dac54ed825",
    "9740051e9c5fecf64344f7a82260edcc",
    "304c6528f659c77866a510d9c1d6ae5e",
);

fn aes_ofb(direction: CipherDirection, input: &[u8]) -> Vec<u8> {
    let key = hex(KEY);
    let iv = hex(IV);
    let mut mode = OfbBlockCipher::new(AesEngine::new(), 128).unwrap();
    mode.init(
        direction,
        &OfbParams::with_iv(AesParams::new(&key).unwrap(), &iv),
    )
    .unwrap();
    run(&mut mode, input)
}

#[test]
fn nist_ofb128_encrypt() {
    assert_eq!(
        aes_ofb(CipherDirection::Encrypt, &hex(PLAINTEXT)),
        hex(OFB128_CIPHERTEXT)
    );
}

#[test]
fn ofb_ignores_the_direction() {
    // keystream 只由 key 與 IV 決定，加解密是同一操作。
    let as_encrypt = aes_ofb(CipherDirection::Encrypt, &hex(PLAINTEXT));
    let as_decrypt = aes_ofb(CipherDirection::Decrypt, &hex(PLAINTEXT));
    assert_eq!(as_encrypt, as_decrypt);
    // 對密文再跑一次即還原。
    assert_eq!(
        aes_ofb(CipherDirection::Decrypt, &as_encrypt),
        hex(PLAINTEXT)
    );
}

#[test]
fn ofb_reports_its_composed_name() {
    let mode = OfbBlockCipher::new(AesEngine::new(), 128).unwrap();
    assert_eq!(mode.algorithm_name(), "AES/OFB128");
}

// ---- CTR (SIC) ----

const CTR_CIPHERTEXT: &str = concat!(
    "874d6191b620e3261bef6864990db6ce",
    "9806f66b7970fdff8617187bb9fffdff",
    "5ae4df3edbd5d35e5b4f09020db03eab",
    "1e031dda2fbe03d1792170a0f3009cee",
);

fn aes_ctr(direction: CipherDirection, input: &[u8]) -> Vec<u8> {
    let key = hex(KEY);
    let iv = hex(CTR_IV);
    let mut mode = SicBlockCipher::new(AesEngine::new());
    mode.init(
        direction,
        &SicParams::new(AesParams::new(&key).unwrap(), &iv),
    )
    .unwrap();
    run(&mut mode, input)
}

#[test]
fn nist_ctr_encrypt() {
    assert_eq!(
        aes_ctr(CipherDirection::Encrypt, &hex(PLAINTEXT)),
        hex(CTR_CIPHERTEXT)
    );
}

#[test]
fn ctr_round_trips_and_ignores_the_direction() {
    let ct = aes_ctr(CipherDirection::Encrypt, &hex(PLAINTEXT));
    assert_eq!(aes_ctr(CipherDirection::Decrypt, &ct), hex(PLAINTEXT));
}

#[test]
fn ctr_counter_carries_across_the_whole_block() {
    // IV 全為 0xFF，第一次遞增必須讓整個計數器進位回零。
    let key = hex(KEY);
    let iv = vec![0xffu8; AES_BLOCK_BYTES];
    let mut mode = SicBlockCipher::new(AesEngine::new());
    mode.init(
        CipherDirection::Encrypt,
        &SicParams::new(AesParams::new(&key).unwrap(), &iv),
    )
    .unwrap();

    let zeros = [0u8; AES_BLOCK_BYTES * 2];
    let keystream = run(&mut mode, &zeros);

    // 第二塊的 keystream 應等於以全零計數器加密的結果。
    let mut bare = AesEngine::new();
    bare.init(CipherDirection::Encrypt, &AesParams::new(&key).unwrap())
        .unwrap();
    let mut expected = [0u8; AES_BLOCK_BYTES];
    bare.process_block(&[0u8; AES_BLOCK_BYTES], &mut expected)
        .unwrap();
    assert_eq!(keystream[AES_BLOCK_BYTES..], expected[..]);
}

#[test]
fn ctr_rejects_an_iv_leaving_no_room_for_the_counter() {
    let key = hex(KEY);
    // AES 分組 16 bytes，計數器上限 min(8, 16/2) = 8，故 IV 至少要 8 bytes。
    let short_iv = hex("0001020304");
    let mut mode = SicBlockCipher::new(AesEngine::new());
    let err = mode
        .init(
            CipherDirection::Encrypt,
            &SicParams::new(AesParams::new(&key).unwrap(), &short_iv),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        BlockCipherModeError::InvalidIvLength {
            actual: 5,
            block_size: 16
        }
    ));
}

#[test]
fn ctr_reports_its_composed_name() {
    let mode = SicBlockCipher::new(AesEngine::new());
    assert_eq!(mode.algorithm_name(), "AES/SIC");
    assert_eq!(mode.block_size(), AES_BLOCK_BYTES);
}

#[test]
fn keystream_modes_error_before_init() {
    let input = [0u8; AES_BLOCK_BYTES];
    let mut out = [0u8; AES_BLOCK_BYTES];

    let mut cfb = CfbBlockCipher::new(AesEngine::new(), 128).unwrap();
    assert!(matches!(
        cfb.process_block(&input, &mut out),
        Err(BlockCipherModeError::NotInitialised)
    ));

    let mut ofb = OfbBlockCipher::new(AesEngine::new(), 128).unwrap();
    assert!(matches!(
        ofb.process_block(&input, &mut out),
        Err(BlockCipherModeError::NotInitialised)
    ));

    let mut ctr = SicBlockCipher::new(AesEngine::new());
    assert!(matches!(
        ctr.process_block(&input, &mut out),
        Err(BlockCipherModeError::NotInitialised)
    ));
}
