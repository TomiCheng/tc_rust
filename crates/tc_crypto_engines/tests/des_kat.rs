//! DES vectors from FIPS 46/81 and Bouncy Castle's `DESTest.cs`.

use tc_crypto_core::BlockCipher;
use tc_crypto_engines::{DES_BLOCK_BYTES, DesEngine, DesParams};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn run_block_vector(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = DesParams::new(&key).unwrap();
    let mut engine = DesEngine::new();

    engine.init(true, &params).unwrap();
    let mut encrypted = [0u8; DES_BLOCK_BYTES];
    assert_eq!(
        engine.process_block(&plaintext, &mut encrypted).unwrap(),
        DES_BLOCK_BYTES
    );
    assert_eq!(encrypted.as_slice(), ciphertext);

    engine.init(false, &params).unwrap();
    let mut recovered = [0u8; DES_BLOCK_BYTES];
    engine.process_block(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn standard_single_block_vector() {
    run_block_vector("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405");
}

#[test]
fn weak_key_remains_usable() {
    run_block_vector("0101010101010101", "95F8A5E5DD31D900", "8000000000000000");
}

#[test]
fn bc_fips_81_ecb_vector() {
    let params = DesParams::new(&unhex("0123456789ABCDEF")).unwrap();
    let plaintext = b"Now is the time for all ";
    let ciphertext = unhex("3FA40E8A984D48156A271787AB8883F9893D51EC4B563B53");
    let mut encrypted = [0u8; 24];
    let mut engine = DesEngine::new();
    engine.init(true, &params).unwrap();

    for (input, output) in plaintext
        .chunks_exact(DES_BLOCK_BYTES)
        .zip(encrypted.chunks_exact_mut(DES_BLOCK_BYTES))
    {
        engine.process_block(input, output).unwrap();
    }
    assert_eq!(encrypted.as_slice(), ciphertext);

    let mut recovered = [0u8; 24];
    engine.init(false, &params).unwrap();
    for (input, output) in ciphertext
        .chunks_exact(DES_BLOCK_BYTES)
        .zip(recovered.chunks_exact_mut(DES_BLOCK_BYTES))
    {
        engine.process_block(input, output).unwrap();
    }
    assert_eq!(&recovered, plaintext);
}
