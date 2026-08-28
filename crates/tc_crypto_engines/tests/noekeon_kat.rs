//! Noekeon ECB vectors from Bouncy Castle's `NoekeonTest.cs`.

use tc_crypto_core::BlockCipher;
use tc_crypto_engines::{NoekeonEngine, NoekeonParams};

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
    let params = NoekeonParams::new(&key).unwrap();
    let mut engine = NoekeonEngine::new();
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
        "00000000000000000000000000000000",
        "b1656851699e29fa24b70148503d2dfc",
    );
    run_vector(
        "ffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffff",
        "2a78421b87c7d0924f26113f1d1349b2",
    );
    run_vector(
        "b1656851699e29fa24b70148503d2dfc",
        "2a78421b87c7d0924f26113f1d1349b2",
        "e2f687e07b75660ffc372233bc47532c",
    );
}
