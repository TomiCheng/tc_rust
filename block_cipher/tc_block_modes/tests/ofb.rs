//! OFB：NIST SP 800-38A F.4 的 AES-128 向量，以及方向、重設、feedback 長度與錯誤處理。

mod common;

use common::{
    IV, KEY, PLAINTEXT, assert_only_the_first_segment_is_written, assert_vectors,
    process, unhex,
};
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_block_modes::{
    BlockCipherMode, BlockModeError, BlockModeInitError, FixedOfbBlockCipher, KeyWithIvRef,
};

/// F.4.1 OFB-AES128。
const CIPHERTEXT: &str = concat!(
    "3b3fd92eb72dad20333449f8e83cfb4a",
    "7789508d16918f03f53c52dac54ed825",
    "9740051e9c5fecf64344f7a82260edcc",
    "304c6528f659c77866a510d9c1d6ae5e",
);

type FixedAesOfb = FixedOfbBlockCipher<AesEngine, 16, 16>;

#[test]
fn ofb_matches_the_nist_sp800_38a_aes128_vectors() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = KeyWithIvRef::new(&key, &iv);
    let (plaintext, ciphertext) = (unhex(PLAINTEXT), unhex(CIPHERTEXT));

    assert_vectors(&mut FixedAesOfb::new(AesEngine::new()), &params, &plaintext, &ciphertext);
    #[cfg(feature = "alloc")]
    assert_vectors(
        &mut tc_block_modes::OfbBlockCipher::new(AesEngine::new(), 128),
        &params,
        &plaintext,
        &ciphertext,
    );
}

#[test]
fn the_requested_direction_does_not_change_the_ofb_output() {
    fn check<M>(mut mode: M)
    where
        M: BlockCipher + for<'a> BlockCipherInit<KeyWithIvRef<'a>>,
    {
        let (key, iv) = (unhex(KEY), unhex(IV));
        let params = KeyWithIvRef::new(&key, &iv);
        let plaintext = unhex(PLAINTEXT);

        let encrypted = process(&mut mode, CipherDirection::Encrypt, &params, &plaintext);
        let decrypted = process(&mut mode, CipherDirection::Decrypt, &params, &plaintext);
        assert_eq!(encrypted, decrypted);
    }

    check(FixedAesOfb::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::OfbBlockCipher::new(AesEngine::new(), 128));
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

    check(FixedAesOfb::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::OfbBlockCipher::new(AesEngine::new(), 128));
}

#[test]
fn reset_restarts_the_keystream_from_the_iv() {
    fn check<M>(mut mode: M)
    where
        M: BlockCipherMode + for<'a> BlockCipherInit<KeyWithIvRef<'a>>,
    {
        let (key, iv) = (unhex(KEY), unhex(IV));
        let plaintext = unhex(PLAINTEXT);
        let ciphertext = unhex(CIPHERTEXT);
        mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
            .unwrap();

        let mut output = [0; 16];
        mode.process_block(&plaintext[..16], &mut output).unwrap();
        mode.process_block(&plaintext[16..32], &mut output).unwrap();
        mode.reset();
        mode.process_block(&plaintext[..16], &mut output).unwrap();
        assert_eq!(output[..], ciphertext[..16]);
    }

    check(FixedAesOfb::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::OfbBlockCipher::new(AesEngine::new(), 128));
}

#[test]
fn an_iv_longer_than_the_block_is_rejected() {
    let key = unhex(KEY);
    let params = KeyWithIvRef::new(&key, &[0; 17]);
    let expected = Err(BlockModeInitError::InvalidIvLength(17));

    assert_eq!(
        FixedAesOfb::new(AesEngine::new()).init(CipherDirection::Encrypt, &params),
        expected
    );
    #[cfg(feature = "alloc")]
    assert_eq!(
        tc_block_modes::OfbBlockCipher::new(AesEngine::new(), 128)
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
        FixedOfbBlockCipher::<_, 16, 0>::new(AesEngine::new()).init(encrypt, &params),
        Err(BlockModeInitError::InvalidFeedbackSize(0))
    );
    assert_eq!(
        FixedOfbBlockCipher::<_, 16, 17>::new(AesEngine::new()).init(encrypt, &params),
        Err(BlockModeInitError::InvalidFeedbackSize(136))
    );
    #[cfg(feature = "alloc")]
    for bits in [0, 12, 136] {
        assert_eq!(
            tc_block_modes::OfbBlockCipher::new(AesEngine::new(), bits).init(encrypt, &params),
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
        let ciphertext = unhex(CIPHERTEXT);
        mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
            .unwrap();
        let mut output = [0; 16];
        mode.process_block(&plaintext[..16], &mut output).unwrap();

        assert_eq!(
            mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key[..15], &[0xaa; 16])),
            Err(BlockModeInitError::Cipher(InitError::InvalidKeyLength(15)))
        );
        mode.process_block(&plaintext[16..32], &mut output).unwrap();
        assert_eq!(output[..], ciphertext[16..32]);

        mode.reset();
        mode.process_block(&plaintext[..16], &mut output).unwrap();
        assert_eq!(output[..], ciphertext[..16]);
    }

    check(FixedAesOfb::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::OfbBlockCipher::new(AesEngine::new(), 128));
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

    check(FixedOfbBlockCipher::<_, 16, 8>::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::OfbBlockCipher::new(AesEngine::new(), 64));
}

#[test]
fn ofb_reports_the_segment_as_its_block_size_and_accepts_partial_blocks() {
    let mode = FixedOfbBlockCipher::<_, 16, 8>::new(AesEngine::new());
    assert_eq!(mode.to_string(), "AES/OFB64");
    assert_eq!(mode.block_size(), 8);
    assert_eq!(mode.underlying_cipher().block_size(), 16);
    assert!(mode.is_partial_block_okay());

    #[cfg(feature = "alloc")]
    {
        let mode = tc_block_modes::OfbBlockCipher::new(AesEngine::new(), 64);
        assert_eq!(mode.to_string(), "AES/OFB64");
        assert_eq!(mode.block_size(), 8);
        assert!(mode.is_partial_block_okay());
    }
}
