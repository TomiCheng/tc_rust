//! CTR：NIST SP 800-38A F.5 的 AES-128 向量，以及計數器、IV 長度與錯誤處理。

mod common;

use common::{
    KEY, PLAINTEXT, aes_encrypt_block, assert_only_the_first_segment_is_written, assert_vectors,
    process, unhex,
};
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_block_modes::{
    BlockCipherMode, BlockModeError, BlockModeInitError, FixedCtrBlockCipher,
    KeyWithIvRef,
};

/// F.5.1 的初始計數器區塊。
const COUNTER: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
/// F.5.1 CTR-AES128。
const CIPHERTEXT: &str = concat!(
    "874d6191b620e3261bef6864990db6ce",
    "9806f66b7970fdff8617187bb9fffdff",
    "5ae4df3edbd5d35e5b4f09020db03eab",
    "1e031dda2fbe03d1792170a0f3009cee",
);

type FixedAesCtr = FixedCtrBlockCipher<AesEngine, 16>;

#[test]
fn ctr_matches_the_nist_sp800_38a_aes128_vectors() {
    let (key, counter) = (unhex(KEY), unhex(COUNTER));
    let params = KeyWithIvRef::new(&key, &counter);
    let (plaintext, ciphertext) = (unhex(PLAINTEXT), unhex(CIPHERTEXT));

    assert_vectors(&mut FixedAesCtr::new(AesEngine::new()), &params, &plaintext, &ciphertext);
    #[cfg(feature = "alloc")]
    assert_vectors(
        &mut tc_block_modes::CtrBlockCipher::new(AesEngine::new()),
        &params,
        &plaintext,
        &ciphertext,
    );
}

#[test]
fn the_requested_direction_does_not_change_the_ctr_output() {
    fn check<M>(mut mode: M)
    where
        M: BlockCipher + for<'a> BlockCipherInit<KeyWithIvRef<'a>>,
    {
        let (key, counter) = (unhex(KEY), unhex(COUNTER));
        let params = KeyWithIvRef::new(&key, &counter);
        let plaintext = unhex(PLAINTEXT);

        let encrypted = process(&mut mode, CipherDirection::Encrypt, &params, &plaintext);
        let decrypted = process(&mut mode, CipherDirection::Decrypt, &params, &plaintext);
        assert_eq!(encrypted, decrypted);
    }

    check(FixedAesCtr::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::CtrBlockCipher::new(AesEngine::new()));
}

#[test]
fn a_short_iv_fills_the_leading_bytes_and_the_counter_starts_at_zero() {
    fn check<M>(mut mode: M)
    where
        M: BlockCipher + for<'a> BlockCipherInit<KeyWithIvRef<'a>>,
    {
        let key = unhex(KEY);
        let nonce = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7];
        let keystream = process(
            &mut mode,
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&key, &nonce),
            &[0; 32],
        );

        let mut counter = [0; 16];
        counter[..8].copy_from_slice(&nonce);
        assert_eq!(keystream[..16], aes_encrypt_block(&key, &counter));
        counter[15] = 1;
        assert_eq!(keystream[16..], aes_encrypt_block(&key, &counter));
    }

    check(FixedAesCtr::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::CtrBlockCipher::new(AesEngine::new()));
}

#[test]
fn the_counter_carries_across_the_whole_block_and_wraps_to_zero() {
    fn check<M>(mut mode: M)
    where
        M: BlockCipher + for<'a> BlockCipherInit<KeyWithIvRef<'a>>,
    {
        let key = unhex(KEY);
        let keystream = process(
            &mut mode,
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&key, &[0xff; 16]),
            &[0; 32],
        );

        assert_eq!(keystream[..16], aes_encrypt_block(&key, &[0xff; 16]));
        assert_eq!(keystream[16..], aes_encrypt_block(&key, &[0; 16]));
    }

    check(FixedAesCtr::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::CtrBlockCipher::new(AesEngine::new()));
}

#[test]
fn the_iv_must_leave_at_most_eight_bytes_of_counter_and_fit_in_the_block() {
    let key = unhex(KEY);
    for length in [0, 7, 17] {
        let iv = vec![0; length];
        let params = KeyWithIvRef::new(&key, &iv);
        let expected = Err(BlockModeInitError::InvalidIvLength(length));

        assert_eq!(
            FixedAesCtr::new(AesEngine::new()).init(CipherDirection::Encrypt, &params),
            expected
        );
        #[cfg(feature = "alloc")]
        assert_eq!(
            tc_block_modes::CtrBlockCipher::new(AesEngine::new())
                .init(CipherDirection::Encrypt, &params),
            expected
        );
    }
    for length in [8, 16] {
        let iv = vec![0; length];
        let params = KeyWithIvRef::new(&key, &iv);

        assert_eq!(
            FixedAesCtr::new(AesEngine::new()).init(CipherDirection::Encrypt, &params),
            Ok(())
        );
        #[cfg(feature = "alloc")]
        assert_eq!(
            tc_block_modes::CtrBlockCipher::new(AesEngine::new())
                .init(CipherDirection::Encrypt, &params),
            Ok(())
        );
    }
}

#[test]
fn reset_restarts_the_counter_from_the_iv() {
    fn check<M>(mut mode: M)
    where
        M: BlockCipherMode + for<'a> BlockCipherInit<KeyWithIvRef<'a>>,
    {
        let (key, counter) = (unhex(KEY), unhex(COUNTER));
        let plaintext = unhex(PLAINTEXT);
        let ciphertext = unhex(CIPHERTEXT);
        mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &counter))
            .unwrap();

        let mut output = [0; 16];
        mode.process_block(&plaintext[..16], &mut output).unwrap();
        mode.process_block(&plaintext[16..32], &mut output).unwrap();
        mode.reset();
        mode.process_block(&plaintext[..16], &mut output).unwrap();
        assert_eq!(output[..], ciphertext[..16]);
    }

    check(FixedAesCtr::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::CtrBlockCipher::new(AesEngine::new()));
}

#[test]
fn a_rejected_initialization_leaves_the_counter_untouched() {
    fn check<M>(mut mode: M)
    where
        M: BlockCipherMode<Error = BlockModeError<BlockError>>
            + for<'a> BlockCipherInit<KeyWithIvRef<'a>, Error = BlockModeInitError<InitError>>,
    {
        let (key, counter) = (unhex(KEY), unhex(COUNTER));
        let plaintext = unhex(PLAINTEXT);
        let ciphertext = unhex(CIPHERTEXT);
        mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &counter))
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

    check(FixedAesCtr::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::CtrBlockCipher::new(AesEngine::new()));
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

        let (key, counter) = (unhex(KEY), unhex(COUNTER));
        mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &counter))
            .unwrap();
        assert_eq!(
            mode.process_block(&[0; 15], &mut [0; 16]),
            Err(BlockModeError::BufferTooShort)
        );
        assert_eq!(
            mode.process_block(&[0; 16], &mut [0; 15]),
            Err(BlockModeError::BufferTooShort)
        );
        assert_only_the_first_segment_is_written(&mut mode);
    }

    check(FixedAesCtr::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::CtrBlockCipher::new(AesEngine::new()));
}

#[test]
fn ctr_reports_its_name_and_accepts_partial_blocks() {
    let mode = FixedAesCtr::new(AesEngine::new());
    assert_eq!(mode.to_string(), "AES/CTR");
    assert_eq!(mode.block_size(), 16);
    assert!(mode.is_partial_block_okay());

    #[cfg(feature = "alloc")]
    {
        let mode = tc_block_modes::CtrBlockCipher::new(AesEngine::new());
        assert_eq!(mode.to_string(), "AES/CTR");
        assert_eq!(mode.block_size(), 16);
        assert!(mode.is_partial_block_okay());
    }
}
