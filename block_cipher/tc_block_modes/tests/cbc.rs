//! CBC：NIST SP 800-38A F.2 的 AES-128 向量，以及 IV、重設與錯誤處理。

mod common;

use common::{
    IV, KEY, PLAINTEXT, assert_only_the_first_segment_is_written, assert_vectors, process, unhex,
};
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_block_modes::{
    BlockCipherMode, BlockModeError, BlockModeInitError, FixedCbcBlockCipher, KeyWithIvFixed,
    KeyWithIvRef,
};

const CIPHERTEXT: &str = concat!(
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7",
);

type FixedAesCbc = FixedCbcBlockCipher<AesEngine, 16>;

#[test]
fn cbc_matches_the_nist_sp800_38a_aes128_vectors() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = KeyWithIvRef::new(&key, &iv);
    let (plaintext, ciphertext) = (unhex(PLAINTEXT), unhex(CIPHERTEXT));

    assert_vectors(&mut FixedAesCbc::new(AesEngine::new()), &params, &plaintext, &ciphertext);
    #[cfg(feature = "alloc")]
    assert_vectors(
        &mut tc_block_modes::CbcBlockCipher::new(AesEngine::new()),
        &params,
        &plaintext,
        &ciphertext,
    );
}

#[test]
fn every_key_with_iv_container_initializes_the_same_cbc_state() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let plaintext = &unhex(PLAINTEXT)[..32];
    let expected = &unhex(CIPHERTEXT)[..32];
    let mut mode = FixedAesCbc::new(AesEngine::new());

    let fixed = KeyWithIvFixed::<16, 16>::new(
        key.clone().try_into().unwrap(),
        iv.clone().try_into().unwrap(),
    );
    assert_eq!(process(&mut mode, CipherDirection::Encrypt, &fixed, plaintext), expected);
    let borrowed = KeyWithIvRef::new(&key, &iv);
    assert_eq!(process(&mut mode, CipherDirection::Encrypt, &borrowed, plaintext), expected);
    #[cfg(feature = "alloc")]
    {
        let owned = tc_block_modes::KeyWithIvOwned::new(key.clone(), iv.clone());
        assert_eq!(process(&mut mode, CipherDirection::Encrypt, &owned, plaintext), expected);
    }
}

#[cfg(feature = "alloc")]
#[test]
fn the_runtime_sized_cbc_treats_an_omitted_iv_as_all_zero() {
    use common::KeyOnly;

    let key = unhex(KEY);
    let plaintext = unhex(PLAINTEXT);
    let mut mode = tc_block_modes::CbcBlockCipher::new(AesEngine::new());

    let omitted = process(&mut mode, CipherDirection::Encrypt, &KeyOnly(&key), &plaintext);
    let zero = process(&mut mode, CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &[0; 16]), &plaintext);
    assert_eq!(omitted, zero);
    // 零 IV 的第一個區塊等於 ECB（F.1.1）。
    assert_eq!(omitted[..16], unhex("3ad77bb40d7a3660a89ecaf32466ef97"));
}

#[test]
fn reset_restores_the_iv_installed_by_the_last_initialization() {
    fn check<M>(mut mode: M)
    where
        M: BlockCipherMode + for<'a> BlockCipherInit<KeyWithIvRef<'a>>,
    {
        let (key, iv) = (unhex(KEY), unhex(IV));
        let plaintext = &unhex(PLAINTEXT)[..16];
        mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
            .unwrap();

        let (mut first, mut chained, mut restarted) = ([0; 16], [0; 16], [0; 16]);
        mode.process_block(plaintext, &mut first).unwrap();
        mode.process_block(plaintext, &mut chained).unwrap();
        mode.reset();
        mode.process_block(plaintext, &mut restarted).unwrap();

        assert_ne!(chained, first);
        assert_eq!(restarted, first);
    }

    check(FixedAesCbc::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::CbcBlockCipher::new(AesEngine::new()));
}

#[test]
fn an_iv_whose_length_differs_from_the_block_is_rejected() {
    let key = unhex(KEY);
    for length in [0, 15, 17] {
        let iv = vec![0; length];
        let params = KeyWithIvRef::new(&key, &iv);
        let expected = Err(BlockModeInitError::InvalidIvLength(length));

        assert_eq!(
            FixedAesCbc::new(AesEngine::new()).init(CipherDirection::Encrypt, &params),
            expected
        );
        #[cfg(feature = "alloc")]
        assert_eq!(
            tc_block_modes::CbcBlockCipher::new(AesEngine::new())
                .init(CipherDirection::Encrypt, &params),
            expected
        );
    }
}

#[test]
fn the_fixed_form_rejects_a_cipher_whose_block_size_is_not_n() {
    let (key, iv) = (unhex(KEY), [0; 8]);
    let mut mode = FixedCbcBlockCipher::<AesEngine, 8>::new(AesEngine::new());

    assert_eq!(
        mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv)),
        Err(BlockModeInitError::UnsupportedBlockSize {
            actual: 16,
            required: 8,
        })
    );
}

#[test]
fn a_rejected_initialization_leaves_the_chaining_state_untouched() {
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

        // 金鑰長度錯誤：底層 cipher 拒絕，新的 IV 也不能生效。
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

    check(FixedAesCbc::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::CbcBlockCipher::new(AesEngine::new()));
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
            mode.process_block(&[0; 15], &mut [0; 16]),
            Err(BlockModeError::BufferTooShort)
        );
        assert_eq!(
            mode.process_block(&[0; 16], &mut [0; 15]),
            Err(BlockModeError::BufferTooShort)
        );
        assert_only_the_first_segment_is_written(&mut mode);
    }

    check(FixedAesCbc::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    check(tc_block_modes::CbcBlockCipher::new(AesEngine::new()));
}

#[test]
fn cbc_reports_its_name_block_size_and_no_partial_blocks() {
    let mut mode = FixedAesCbc::new(AesEngine::new());
    assert_eq!(mode.to_string(), "AES/CBC");
    assert_eq!(mode.block_size(), 16);
    assert!(!mode.is_partial_block_okay());
    let mode: &mut dyn BlockCipherMode<Error = BlockModeError<BlockError>, Cipher = AesEngine> =
        &mut mode;
    assert_eq!(mode.underlying_cipher().block_size(), 16);

    #[cfg(feature = "alloc")]
    {
        let mode = tc_block_modes::CbcBlockCipher::new(AesEngine::new());
        assert_eq!(mode.to_string(), "AES/CBC");
        assert_eq!(mode.block_size(), 16);
        assert!(!mode.is_partial_block_okay());
    }
}
