//! CFB：NIST SP 800-38A F.3 的 AES-128 向量，以及 IV 補齊、feedback 長度與錯誤處理。

mod common;

use common::{
    IV, KEY, PLAINTEXT, assert_only_the_first_segment_is_written, assert_vectors,
    process, unhex,
};
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_block_modes::{
    BlockCipherMode, BlockModeError, BlockModeInitError, FixedCfbBlockCipher, KeyWithIvRef,
};

/// F.3.13 CFB128-AES128。
const CFB128_CIPHERTEXT: &str = concat!(
    "3b3fd92eb72dad20333449f8e83cfb4a",
    "c8a64537a0b3a93fcde3cdad9f1ce58b",
    "26751f67a3cbb140b1808cf187a4f4df",
    "c04b05357c5d1c0eeac4c66f9ff7f2e6",
);
/// F.3.7 CFB8-AES128，18 個一位元組的段。
const CFB8_PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172aae2d";
const CFB8_CIPHERTEXT: &str = "3b79424c9c0dd436bace9e0ed4586a4f32b9";

#[test]
fn cfb128_matches_the_nist_sp800_38a_aes128_vectors() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = KeyWithIvRef::new(&key, &iv);
    let (plaintext, ciphertext) = (unhex(PLAINTEXT), unhex(CFB128_CIPHERTEXT));

    assert_vectors(
        &mut FixedCfbBlockCipher::<_, 16, 16>::new(AesEngine::new()),
        &params,
        &plaintext,
        &ciphertext,
    );
    #[cfg(feature = "alloc")]
    assert_vectors(
        &mut tc_block_modes::CfbBlockCipher::new(AesEngine::new(), 128),
        &params,
        &plaintext,
        &ciphertext,
    );
}

#[test]
fn cfb8_matches_the_nist_sp800_38a_aes128_vectors() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = KeyWithIvRef::new(&key, &iv);
    let (plaintext, ciphertext) = (unhex(CFB8_PLAINTEXT), unhex(CFB8_CIPHERTEXT));

    assert_vectors(
        &mut FixedCfbBlockCipher::<_, 16, 1>::new(AesEngine::new()),
        &params,
        &plaintext,
        &ciphertext,
    );
    #[cfg(feature = "alloc")]
    assert_vectors(
        &mut tc_block_modes::CfbBlockCipher::new(AesEngine::new(), 8),
        &params,
        &plaintext,
        &ciphertext,
    );
}

#[test]
fn a_short_iv_is_right_aligned_over_zeros_so_an_empty_iv_is_all_zero() {
    fn check<M>(mut mode: M)
    where
        M: BlockCipher + for<'a> BlockCipherInit<KeyWithIvRef<'a>>,
    {
        let key = unhex(KEY);
        let plaintext = unhex(PLAINTEXT);
        let encrypt = CipherDirection::Encrypt;

        let short = process(&mut mode, encrypt, &KeyWithIvRef::new(&key, &[1, 2, 3, 4]), &plaintext);
        let mut padded = [0; 16];
        padded[12..].copy_from_slice(&[1, 2, 3, 4]);
        let full = process(&mut mode, encrypt, &KeyWithIvRef::new(&key, &padded), &plaintext);
        assert_eq!(short, full);

        let empty = process(&mut mode, encrypt, &KeyWithIvRef::new(&key, &[]), &plaintext);
        let zero = process(&mut mode, encrypt, &KeyWithIvRef::new(&key, &[0; 16]), &plaintext);
        assert_eq!(empty, zero);
    }

    check(FixedCfbBlockCipher::<_, 16, 16>::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::CfbBlockCipher::new(AesEngine::new(), 128));
}

#[test]
fn an_iv_longer_than_the_block_is_rejected() {
    let key = unhex(KEY);
    let params = KeyWithIvRef::new(&key, &[0; 17]);
    let expected = Err(BlockModeInitError::InvalidIvLength(17));

    assert_eq!(
        FixedCfbBlockCipher::<_, 16, 16>::new(AesEngine::new())
            .init(CipherDirection::Encrypt, &params),
        expected
    );
    #[cfg(feature = "alloc")]
    assert_eq!(
        tc_block_modes::CfbBlockCipher::new(AesEngine::new(), 128)
            .init(CipherDirection::Encrypt, &params),
        expected
    );
}

#[test]
fn a_feedback_size_outside_one_byte_to_one_block_is_rejected_at_initialization() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = KeyWithIvRef::new(&key, &iv);
    let encrypt = CipherDirection::Encrypt;

    assert_eq!(
        FixedCfbBlockCipher::<_, 16, 0>::new(AesEngine::new()).init(encrypt, &params),
        Err(BlockModeInitError::InvalidFeedbackSize(0))
    );
    assert_eq!(
        FixedCfbBlockCipher::<_, 16, 17>::new(AesEngine::new()).init(encrypt, &params),
        Err(BlockModeInitError::InvalidFeedbackSize(136))
    );
    #[cfg(feature = "alloc")]
    for bits in [0, 12, 136] {
        assert_eq!(
            tc_block_modes::CfbBlockCipher::new(AesEngine::new(), bits).init(encrypt, &params),
            Err(BlockModeInitError::InvalidFeedbackSize(bits))
        );
    }
}

#[test]
fn a_rejected_initialization_leaves_the_feedback_register_untouched() {
    fn check<M>(mut mode: M)
    where
        M: BlockCipherMode<Error = BlockModeError<BlockError>>
            + for<'a> BlockCipherInit<KeyWithIvRef<'a>, Error = BlockModeInitError<InitError>>,
    {
        let (key, iv) = (unhex(KEY), unhex(IV));
        let plaintext = unhex(PLAINTEXT);
        let ciphertext = unhex(CFB128_CIPHERTEXT);
        mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
            .unwrap();
        let mut output = [0; 16];
        mode.process_block(&plaintext[..16], &mut output).unwrap();

        assert_eq!(
            mode.init(CipherDirection::Decrypt, &KeyWithIvRef::new(&key[..15], &[0xaa; 16])),
            Err(BlockModeInitError::Cipher(InitError::InvalidKeyLength(15)))
        );
        mode.process_block(&plaintext[16..32], &mut output).unwrap();
        assert_eq!(output[..], ciphertext[16..32]);

        mode.reset();
        mode.process_block(&plaintext[..16], &mut output).unwrap();
        assert_eq!(output[..], ciphertext[..16]);
    }

    check(FixedCfbBlockCipher::<_, 16, 16>::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::CfbBlockCipher::new(AesEngine::new(), 128));
}

#[test]
fn processing_fails_before_initialization_and_on_short_buffers() {
    fn check<M>(mut mode: M)
    where
        M: BlockCipherMode<Error = BlockModeError<BlockError>>
            + for<'a> BlockCipherInit<KeyWithIvRef<'a>>,
    {
        assert_eq!(
            mode.process_block(&[0; 16], &mut [0; 16]),
            Err(BlockModeError::NotInitialised)
        );

        let (key, iv) = (unhex(KEY), unhex(IV));
        mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
            .unwrap();
        assert_eq!(
            mode.process_block(&[0; 7], &mut [0; 8]),
            Err(BlockModeError::BufferTooShort)
        );
        assert_eq!(
            mode.process_block(&[0; 8], &mut [0; 7]),
            Err(BlockModeError::BufferTooShort)
        );
        assert_only_the_first_segment_is_written(&mut mode);
    }

    check(FixedCfbBlockCipher::<_, 16, 8>::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::CfbBlockCipher::new(AesEngine::new(), 64));
}

#[test]
fn cfb_reports_the_segment_as_its_block_size_and_accepts_partial_blocks() {
    let mode = FixedCfbBlockCipher::<_, 16, 8>::new(AesEngine::new());
    assert_eq!(mode.to_string(), "AES/CFB64");
    assert_eq!(mode.block_size(), 8);
    assert_eq!(mode.underlying_cipher().block_size(), 16);
    assert!(mode.is_partial_block_okay());

    #[cfg(feature = "alloc")]
    {
        let mode = tc_block_modes::CfbBlockCipher::new(AesEngine::new(), 64);
        assert_eq!(mode.to_string(), "AES/CFB64");
        assert_eq!(mode.block_size(), 8);
        assert!(mode.is_partial_block_okay());
    }
}
