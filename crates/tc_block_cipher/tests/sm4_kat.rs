//! SM4 ECB vectors from Bouncy Castle's `SM4Test.cs` (eprint 2008/329).

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_block_cipher::{Sm4Engine, Sm4Params};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn bc_ecb_vector() {
    let key = unhex("0123456789abcdeffedcba9876543210");
    let plaintext = unhex("0123456789abcdeffedcba9876543210");
    let ciphertext = unhex("681edf34d206965e86b3e94f536e4246");
    let params = Sm4Params::new(&key).unwrap();
    let mut engine = Sm4Engine::new();
    let mut output = vec![0u8; 16];

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(engine.process_block(&plaintext, &mut output).unwrap(), 16);
    assert_eq!(output, ciphertext);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(output, plaintext);
}

#[test]
fn bc_one_million_iterations() {
    let key = unhex("0123456789abcdeffedcba9876543210");
    let plaintext = unhex("0123456789abcdeffedcba9876543210");
    let expected = unhex("595298c7c6fd271f0402f804c33d3f66");
    let params = Sm4Params::new(&key).unwrap();

    let mut engine = Sm4Engine::new();
    let mut buf = plaintext.clone();
    let mut tmp = vec![0u8; 16];

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    for _ in 0..1_000_000 {
        engine.process_block(&buf, &mut tmp).unwrap();
        buf.copy_from_slice(&tmp);
    }
    assert_eq!(buf, expected);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    for _ in 0..1_000_000 {
        engine.process_block(&buf, &mut tmp).unwrap();
        buf.copy_from_slice(&tmp);
    }
    assert_eq!(buf, plaintext);
}
