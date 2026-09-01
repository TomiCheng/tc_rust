//! RC6 vectors from Bouncy Castle's `RC6Test.cs` and the AES submission.

mod common;

use common::unhex;
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_params::KeyRef;
use tc_rc6::{BLOCK_BYTES, Rc6Engine};

fn assert_vector(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = KeyRef::new(&key);
    let mut engine = Rc6Engine::new();
    let mut output = [0u8; BLOCK_BYTES];

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(
        engine.process_block(&plaintext, &mut output).unwrap(),
        BLOCK_BYTES
    );
    assert_eq!(output.as_slice(), ciphertext);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(output.as_slice(), plaintext);
}

#[test]
fn bc_ecb_vectors() {
    assert_vector(
        "00000000000000000000000000000000",
        "80000000000000000000000000000000",
        "f71f65e7b80c0c6966fee607984b5cdf",
    );
    assert_vector(
        "000000000000000000000000000000008000000000000000",
        "00000000000000000000000000000000",
        "dd04c176440bbc6686c90aee775bd368",
    );
    assert_vector(
        "000000000000000000000000000000000000001000000000",
        "00000000000000000000000000000000",
        "937fe02d20fcb72f0f57201012b88ba4",
    );
    assert_vector(
        "00000001000000000000000000000000",
        "00000000000000000000000000000000",
        "8a380594d7396453771a1dfbe2914c8e",
    );
    assert_vector(
        "1000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "11395d4bfe4c8258979ee2bf2d24dff4",
    );
    assert_vector(
        "0000000000000000000000000000000000080000000000000000000000000000",
        "00000000000000000000000000000000",
        "3d6f7e99f6512553bb983e8f75672b97",
    );
}
