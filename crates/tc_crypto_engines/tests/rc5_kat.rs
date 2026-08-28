//! RC5 vectors (RFC 2040) from Bouncy Castle's `RC5Test.cs`.
//!
//! BC exercises RC5 through CBC; every vector is a single block, so CBC reduces
//! to `E(pt XOR iv)` and the raw ECB engine can be checked by XOR-ing the IV.

use tc_crypto_core::BlockCipher;
use tc_crypto_engines::{Rc532Engine, Rc564Engine, Rc5Params};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

fn run_rc5_32(rounds: usize, key: &str, iv: &str, plaintext: &str, ciphertext: &str) {
    run::<Rc532Engine>(8, rounds, key, iv, plaintext, ciphertext);
}

fn run_rc5_64(rounds: usize, key: &str, iv: &str, plaintext: &str, ciphertext: &str) {
    run::<Rc564Engine>(16, rounds, key, iv, plaintext, ciphertext);
}

fn run<E>(block: usize, rounds: usize, key: &str, iv: &str, plaintext: &str, ciphertext: &str)
where
    E: BlockCipher<Error = tc_crypto_engines::BlockCipherError> + Default,
    for<'a> E: BlockCipher<Params<'a> = Rc5Params>,
{
    let key = unhex(key);
    let iv = unhex(iv);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = Rc5Params::with_rounds(&key, rounds).unwrap();

    let mut engine = E::default();
    engine.init(true, &params).unwrap();
    let mut output = vec![0u8; block];
    assert_eq!(
        engine.process_block(&xor(&plaintext, &iv), &mut output).unwrap(),
        block
    );
    assert_eq!(output, ciphertext);

    engine.init(false, &params).unwrap();
    engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(xor(&output, &iv), plaintext);
}

#[test]
fn bc_rc5_32_vectors() {
    run_rc5_32(0, "00", "0000000000000000", "0000000000000000", "7a7bba4d79111d1e");
    run_rc5_32(0, "00", "0000000000000000", "ffffffffffffffff", "797bba4d78111d1e");
    run_rc5_32(0, "00", "0000000000000001", "0000000000000000", "7a7bba4d79111d1f");
    run_rc5_32(0, "00", "0000000000000000", "0000000000000001", "7a7bba4d79111d1f");
    run_rc5_32(0, "00", "0102030405060708", "1020304050607080", "8b9ded91ce7794a6");
    run_rc5_32(1, "11", "0000000000000000", "0000000000000000", "2f759fe7ad86a378");
    run_rc5_32(2, "00", "0000000000000000", "0000000000000000", "dca2694bf40e0788");
    run_rc5_32(2, "00000000", "0000000000000000", "0000000000000000", "dca2694bf40e0788");
    run_rc5_32(8, "00000000", "0000000000000000", "0000000000000000", "dcfe098577eca5ff");
    run_rc5_32(8, "00", "0102030405060708", "1020304050607080", "9646fb77638f9ca8");
    run_rc5_32(12, "00", "0102030405060708", "1020304050607080", "b2b3209db6594da4");
    run_rc5_32(16, "00", "0102030405060708", "1020304050607080", "545f7f32a5fc3836");
    run_rc5_32(8, "01020304", "0000000000000000", "ffffffffffffffff", "8285e7c1b5bc7402");
    run_rc5_32(12, "01020304", "0000000000000000", "ffffffffffffffff", "fc586f92f7080934");
    run_rc5_32(16, "01020304", "0000000000000000", "ffffffffffffffff", "cf270ef9717ff7c4");
    run_rc5_32(12, "0102030405060708", "0000000000000000", "ffffffffffffffff", "e493f1c1bb4d6e8c");
    run_rc5_32(8, "0102030405060708", "0102030405060708", "1020304050607080", "5c4c041e0f217ac3");
    run_rc5_32(12, "0102030405060708", "0102030405060708", "1020304050607080", "921f12485373b4f7");
    run_rc5_32(16, "0102030405060708", "0102030405060708", "1020304050607080", "5ba0ca6bbe7f5fad");
    run_rc5_32(8, "01020304050607081020304050607080", "0102030405060708", "1020304050607080", "c533771cd0110e63");
    run_rc5_32(12, "01020304050607081020304050607080", "0102030405060708", "1020304050607080", "294ddb46b3278d60");
    run_rc5_32(16, "01020304050607081020304050607080", "0102030405060708", "1020304050607080", "dad6bda9dfe8f7e8");
    run_rc5_32(12, "0102030405", "0000000000000000", "ffffffffffffffff", "97e0787837ed317f");
    run_rc5_32(8, "0102030405", "0000000000000000", "ffffffffffffffff", "7875dbf6738c6478");
    run_rc5_32(8, "0102030405", "7875dbf6738c6478", "0808080808080808", "8f34c3c681c99695");
}

#[test]
fn bc_rc5_64_vectors() {
    run_rc5_64(
        0,
        "00",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "9f09b98d3f6062d9d4d59973d00e0e63",
    );
    run_rc5_64(
        0,
        "00",
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "9e09b98d3f6062d9d3d59973d00e0e63",
    );
}
