//! Tests for CBC mode.
//!
//! The AES vectors are from NIST SP 800-38A §F.2 (CBC-AES128), which chains four
//! blocks — enough to exercise the chaining itself rather than just the first
//! block. A DES vector covers a cipher whose block size is not 16 bytes, and the
//! remaining tests cover the default IV, round-tripping, and the error paths.

use tc_block_cipher::{
    AES_BLOCK_BYTES, AesEngine, AesParams, DES_BLOCK_BYTES, DesEngine, DesParams,
};
use tc_block_modes::{BlockCipherModeError, CbcBlockCipher, CbcParams};
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

/// Parses a hex string into bytes.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const AES_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const AES_IV: &str = "000102030405060708090a0b0c0d0e0f";
const AES_PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);
const AES_CIPHERTEXT: &str = concat!(
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7",
);

/// Runs every block of `input` through a freshly initialised AES-CBC mode.
fn aes_cbc(direction: CipherDirection, iv: Option<&[u8]>, input: &[u8]) -> Vec<u8> {
    let key = hex(AES_KEY);
    let key_params = AesParams::new(&key).unwrap();
    let params = match iv {
        Some(iv) => CbcParams::with_iv(key_params, iv),
        None => CbcParams::new(key_params),
    };

    let mut mode = CbcBlockCipher::new(AesEngine::new());
    mode.init(direction, &params).unwrap();

    let mut out = vec![0u8; input.len()];
    for (chunk_in, chunk_out) in input
        .chunks(AES_BLOCK_BYTES)
        .zip(out.chunks_mut(AES_BLOCK_BYTES))
    {
        let n = mode.process_block(chunk_in, chunk_out).unwrap();
        assert_eq!(n, AES_BLOCK_BYTES);
    }
    out
}

#[test]
fn nist_sp800_38a_aes128_encrypt() {
    let iv = hex(AES_IV);
    assert_eq!(
        aes_cbc(CipherDirection::Encrypt, Some(&iv), &hex(AES_PLAINTEXT)),
        hex(AES_CIPHERTEXT)
    );
}

#[test]
fn nist_sp800_38a_aes128_decrypt() {
    let iv = hex(AES_IV);
    assert_eq!(
        aes_cbc(CipherDirection::Decrypt, Some(&iv), &hex(AES_CIPHERTEXT)),
        hex(AES_PLAINTEXT)
    );
}

#[test]
fn omitted_iv_defaults_to_zeros() {
    // 未給 IV 時視為全零（照 bc）。
    let zero_iv = vec![0u8; AES_BLOCK_BYTES];
    let with_zeros = aes_cbc(
        CipherDirection::Encrypt,
        Some(&zero_iv),
        &hex(AES_PLAINTEXT),
    );
    let omitted = aes_cbc(CipherDirection::Encrypt, None, &hex(AES_PLAINTEXT));
    assert_eq!(omitted, with_zeros);
    assert_eq!(
        omitted[..AES_BLOCK_BYTES],
        hex("3ad77bb40d7a3660a89ecaf32466ef97")[..]
    );
}

#[test]
fn chaining_hides_repeated_blocks() {
    // 兩塊相同明文，在 CBC 下必須產生不同密文——這正是 ECB 做不到的。
    let iv = hex(AES_IV);
    let repeated = hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    let ct = aes_cbc(CipherDirection::Encrypt, Some(&iv), &repeated);
    assert_ne!(ct[..AES_BLOCK_BYTES], ct[AES_BLOCK_BYTES..]);
}

#[test]
fn des_cbc_handles_an_eight_byte_block() {
    let key = DesParams::new(&hex("0123456789abcdef")).unwrap();
    let iv = hex("1234567890abcdef");
    let plaintext = hex("0011223344556677889aabbccddeeff0");

    let mut mode = CbcBlockCipher::new(DesEngine::new());
    assert_eq!(mode.block_size(), DES_BLOCK_BYTES);
    mode.init(CipherDirection::Encrypt, &CbcParams::with_iv(key, &iv))
        .unwrap();

    let mut ct = vec![0u8; plaintext.len()];
    for (chunk_in, chunk_out) in plaintext
        .chunks(DES_BLOCK_BYTES)
        .zip(ct.chunks_mut(DES_BLOCK_BYTES))
    {
        mode.process_block(chunk_in, chunk_out).unwrap();
    }
    assert_eq!(ct, hex("ea2f68f28421d42f78ecb43cd67c0345"));
}

#[test]
fn reports_composed_algorithm_name_and_block_size() {
    let mode = CbcBlockCipher::new(AesEngine::new());
    assert_eq!(mode.algorithm_name(), "AES/CBC");
    assert_eq!(mode.block_size(), AES_BLOCK_BYTES);
}

#[test]
fn rejects_an_iv_that_is_not_one_block() {
    let key = AesParams::new(&hex(AES_KEY)).unwrap();
    let short_iv = hex("00010203");

    let mut mode = CbcBlockCipher::new(AesEngine::new());
    let err = mode
        .init(
            CipherDirection::Encrypt,
            &CbcParams::with_iv(key, &short_iv),
        )
        .unwrap_err();

    match err {
        BlockCipherModeError::InvalidIvLength { actual, block_size } => {
            assert_eq!(actual, 4);
            assert_eq!(block_size, AES_BLOCK_BYTES);
        }
        other => panic!("expected InvalidIvLength, got {other:?}"),
    }
}

#[test]
fn errors_before_init_and_on_short_buffer() {
    let mut mode = CbcBlockCipher::new(AesEngine::new());
    let input = hex(AES_PLAINTEXT);
    let mut out = [0u8; AES_BLOCK_BYTES];

    // 尚未 init。
    assert!(matches!(
        mode.process_block(&input, &mut out),
        Err(BlockCipherModeError::NotInitialised)
    ));

    let key = AesParams::new(&hex(AES_KEY)).unwrap();
    mode.init(CipherDirection::Encrypt, &CbcParams::new(key))
        .unwrap();

    // 輸入不足一塊。
    assert!(matches!(
        mode.process_block(&input[..4], &mut out),
        Err(BlockCipherModeError::BufferTooShort)
    ));
}
