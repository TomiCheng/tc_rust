//! RC6 ECB vectors (AES-submission reference) from Bouncy Castle's `RC6Test.cs`.

use tc_crypto_core::BlockCipher;
use tc_crypto_engines::{Rc6Engine, Rc6Params};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn run_vector(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = Rc6Params::new(&key).unwrap();
    let mut engine = Rc6Engine::new();
    let mut output = vec![0u8; 16];

    engine.init(true, &params).unwrap();
    assert_eq!(engine.process_block(&plaintext, &mut output).unwrap(), 16);
    assert_eq!(output, ciphertext);

    engine.init(false, &params).unwrap();
    engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(output, plaintext);
}

#[test]
fn bc_ecb_vectors() {
    run_vector(
        "00000000000000000000000000000000",
        "80000000000000000000000000000000",
        "f71f65e7b80c0c6966fee607984b5cdf",
    );
    run_vector(
        "000000000000000000000000000000008000000000000000",
        "00000000000000000000000000000000",
        "dd04c176440bbc6686c90aee775bd368",
    );
    run_vector(
        "000000000000000000000000000000000000001000000000",
        "00000000000000000000000000000000",
        "937fe02d20fcb72f0f57201012b88ba4",
    );
    run_vector(
        "00000001000000000000000000000000",
        "00000000000000000000000000000000",
        "8a380594d7396453771a1dfbe2914c8e",
    );
    run_vector(
        "1000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "11395d4bfe4c8258979ee2bf2d24dff4",
    );
    run_vector(
        "0000000000000000000000000000000000080000000000000000000000000000",
        "00000000000000000000000000000000",
        "3d6f7e99f6512553bb983e8f75672b97",
    );
}
