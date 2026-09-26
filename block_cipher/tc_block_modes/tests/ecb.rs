//! ECB：NIST SP 800-38A F.1 的 AES-128 向量與轉發行為。

mod common;

use common::{KEY, PLAINTEXT, assert_only_the_first_segment_is_written, assert_vectors, unhex};
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef};
use tc_block_modes::{BlockCipherMode, EcbBlockCipher};

const CIPHERTEXT: &str = concat!(
    "3ad77bb40d7a3660a89ecaf32466ef97",
    "f5d3d58503b9699de785895a96fdbaaf",
    "43b1cd7f598ece23881b00e3ed030688",
    "7b0c785e27e8ad3f8223207104725dd4",
);

#[test]
fn ecb_matches_the_nist_sp800_38a_aes128_vectors() {
    let key = unhex(KEY);
    assert_vectors(
        &mut EcbBlockCipher::new(AesEngine::new()),
        &KeyRef::new(&key),
        &unhex(PLAINTEXT),
        &unhex(CIPHERTEXT),
    );
}

#[test]
fn ecb_passes_the_underlying_cipher_errors_through_unchanged() {
    let mut mode = EcbBlockCipher::new(AesEngine::new());
    assert_eq!(
        mode.process_block(&[0; 16], &mut [0; 16]),
        Err(BlockError::NotInitialised)
    );
    assert_eq!(
        mode.init(CipherDirection::Encrypt, &KeyRef::new(&[0; 15])),
        Err(InitError::InvalidKeyLength(15))
    );

    mode.init(CipherDirection::Encrypt, &KeyRef::new(&[0; 16]))
        .unwrap();
    assert_eq!(
        mode.process_block(&[0; 15], &mut [0; 16]),
        Err(BlockError::BufferTooShort)
    );
    assert_only_the_first_segment_is_written(&mut mode);
}

#[test]
fn ecb_reports_the_cipher_name_block_size_and_no_partial_blocks() {
    let mut mode = EcbBlockCipher::new(AesEngine::new());
    assert_eq!(mode.to_string(), "AES/ECB");
    assert_eq!(mode.block_size(), 16);
    assert_eq!(mode.underlying_cipher().block_size(), 16);
    assert!(!mode.is_partial_block_okay());

    let mode: &mut dyn BlockCipherMode<Error = BlockError, Cipher = AesEngine> = &mut mode;
    mode.reset();
    assert_eq!(mode.block_size(), 16);
}
