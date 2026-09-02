//! SKIPJACK ECB vector from Bouncy Castle's `SkipjackTest.cs`.

mod common;

use common::unhex;
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_params::KeyRef;
use tc_skipjack::{BLOCK_BYTES, SkipjackEngine};

#[test]
fn bc_ecb_vector() {
    let key = unhex("00998877665544332211");
    let plaintext = unhex("33221100ddccbbaa");
    let ciphertext = unhex("2587cae27a12d300");
    let params = KeyRef::new(&key);
    let mut engine = SkipjackEngine::new();

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = [0u8; BLOCK_BYTES];
    assert_eq!(
        engine.process_block(&plaintext, &mut encrypted).unwrap(),
        BLOCK_BYTES
    );
    assert_eq!(encrypted.as_slice(), ciphertext);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; BLOCK_BYTES];
    engine.process_block(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}
