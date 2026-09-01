//! RC5 vectors from Bouncy Castle's `RC5Test.cs` and RFC 2040.
//!
//! Bouncy Castle exercises RC5 through CBC. Each vector is one block, so the
//! raw block-cipher input is `plaintext XOR IV`.

mod common;

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_rc5::{Params, Rc532Engine, Rc564Engine};

use common::{unhex, xor};

fn run<E>(
    mut engine: E,
    rounds: usize,
    block_bytes: usize,
    key: &str,
    iv: &str,
    plaintext: &str,
    ciphertext: &str,
) where
    E: BlockCipher<Error = BlockError> + BlockCipherInit<Error = InitError>,
    for<'a> E: BlockCipherInit<Params<'a> = dyn tc_rc5::Rc5Params + 'a, Error = InitError>,
{
    let key = unhex(key);
    let iv = unhex(iv);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = Params::new(&key, rounds);

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut output = vec![0u8; block_bytes];
    assert_eq!(
        engine
            .process_block(&xor(&plaintext, &iv), &mut output)
            .unwrap(),
        block_bytes
    );
    assert_eq!(output, ciphertext);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(xor(&output, &iv), plaintext);
}

fn run32(rounds: usize, key: &str, iv: &str, plaintext: &str, ciphertext: &str) {
    run(
        Rc532Engine::new(),
        rounds,
        8,
        key,
        iv,
        plaintext,
        ciphertext,
    );
}

fn run64(rounds: usize, key: &str, iv: &str, plaintext: &str, ciphertext: &str) {
    run(
        Rc564Engine::new(),
        rounds,
        16,
        key,
        iv,
        plaintext,
        ciphertext,
    );
}

#[test]
fn bc_rc5_32_vectors() {
    run32(
        0,
        "00",
        "0000000000000000",
        "0000000000000000",
        "7a7bba4d79111d1e",
    );
    run32(
        0,
        "00",
        "0000000000000000",
        "ffffffffffffffff",
        "797bba4d78111d1e",
    );
    run32(
        0,
        "00",
        "0000000000000001",
        "0000000000000000",
        "7a7bba4d79111d1f",
    );
    run32(
        0,
        "00",
        "0000000000000000",
        "0000000000000001",
        "7a7bba4d79111d1f",
    );
    run32(
        0,
        "00",
        "0102030405060708",
        "1020304050607080",
        "8b9ded91ce7794a6",
    );
    run32(
        1,
        "11",
        "0000000000000000",
        "0000000000000000",
        "2f759fe7ad86a378",
    );
    run32(
        2,
        "00",
        "0000000000000000",
        "0000000000000000",
        "dca2694bf40e0788",
    );
    run32(
        2,
        "00000000",
        "0000000000000000",
        "0000000000000000",
        "dca2694bf40e0788",
    );
    run32(
        8,
        "00000000",
        "0000000000000000",
        "0000000000000000",
        "dcfe098577eca5ff",
    );
    run32(
        8,
        "00",
        "0102030405060708",
        "1020304050607080",
        "9646fb77638f9ca8",
    );
    run32(
        12,
        "00",
        "0102030405060708",
        "1020304050607080",
        "b2b3209db6594da4",
    );
    run32(
        16,
        "00",
        "0102030405060708",
        "1020304050607080",
        "545f7f32a5fc3836",
    );
    run32(
        8,
        "01020304",
        "0000000000000000",
        "ffffffffffffffff",
        "8285e7c1b5bc7402",
    );
    run32(
        12,
        "01020304",
        "0000000000000000",
        "ffffffffffffffff",
        "fc586f92f7080934",
    );
    run32(
        16,
        "01020304",
        "0000000000000000",
        "ffffffffffffffff",
        "cf270ef9717ff7c4",
    );
    run32(
        12,
        "0102030405060708",
        "0000000000000000",
        "ffffffffffffffff",
        "e493f1c1bb4d6e8c",
    );
    run32(
        8,
        "0102030405060708",
        "0102030405060708",
        "1020304050607080",
        "5c4c041e0f217ac3",
    );
    run32(
        12,
        "0102030405060708",
        "0102030405060708",
        "1020304050607080",
        "921f12485373b4f7",
    );
    run32(
        16,
        "0102030405060708",
        "0102030405060708",
        "1020304050607080",
        "5ba0ca6bbe7f5fad",
    );
    run32(
        8,
        "01020304050607081020304050607080",
        "0102030405060708",
        "1020304050607080",
        "c533771cd0110e63",
    );
    run32(
        12,
        "01020304050607081020304050607080",
        "0102030405060708",
        "1020304050607080",
        "294ddb46b3278d60",
    );
    run32(
        16,
        "01020304050607081020304050607080",
        "0102030405060708",
        "1020304050607080",
        "dad6bda9dfe8f7e8",
    );
    run32(
        12,
        "0102030405",
        "0000000000000000",
        "ffffffffffffffff",
        "97e0787837ed317f",
    );
    run32(
        8,
        "0102030405",
        "0000000000000000",
        "ffffffffffffffff",
        "7875dbf6738c6478",
    );
    run32(
        8,
        "0102030405",
        "7875dbf6738c6478",
        "0808080808080808",
        "8f34c3c681c99695",
    );
}

#[test]
fn bc_rc5_64_vectors() {
    run64(
        0,
        "00",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "9f09b98d3f6062d9d4d59973d00e0e63",
    );
    run64(
        0,
        "00",
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "9e09b98d3f6062d9d3d59973d00e0e63",
    );
}
