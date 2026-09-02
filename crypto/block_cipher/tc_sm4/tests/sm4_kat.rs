//! SM4 ECB vectors from Bouncy Castle's `SM4Test.cs` (eprint 2008/329).

mod common;

use common::unhex;
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_params::KeyRef;
use tc_sm4::{BLOCK_BYTES, Sm4Engine};

const KEY: &str = "0123456789abcdeffedcba9876543210";
const PLAINTEXT: &str = "0123456789abcdeffedcba9876543210";

#[test]
fn bc_ecb_vector() {
    let key = unhex(KEY);
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = unhex("681edf34d206965e86b3e94f536e4246");
    let params = KeyRef::new(&key);
    let mut engine = Sm4Engine::new();

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

/// Bouncy Castle's million-iteration vector, and the same count back again.
#[test]
fn bc_one_million_iterations() {
    let key = unhex(KEY);
    let plaintext = unhex(PLAINTEXT);
    let params = KeyRef::new(&key);
    let mut engine = Sm4Engine::new();

    let mut block: [u8; BLOCK_BYTES] = plaintext.clone().try_into().unwrap();
    let mut output = [0u8; BLOCK_BYTES];

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    for _ in 0..1_000_000 {
        engine.process_block(&block, &mut output).unwrap();
        block = output;
    }
    assert_eq!(block.as_slice(), unhex("595298c7c6fd271f0402f804c33d3f66"));

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    for _ in 0..1_000_000 {
        engine.process_block(&block, &mut output).unwrap();
        block = output;
    }
    assert_eq!(block.as_slice(), plaintext);
}
