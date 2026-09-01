//! DES vectors from FIPS 46/81 and Bouncy Castle's `DESTest.cs`.

mod common;

use common::unhex;
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_des::{BLOCK_BYTES, DesEngine};
use tc_params::KeyRef;

fn run_block_vector(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = KeyRef::new(&key);
    let mut engine = DesEngine::new();

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
    let key = unhex("0123456789ABCDEF");
    let params = KeyRef::new(&key);
    let plaintext = b"Now is the time for all ";
    let ciphertext = unhex("3FA40E8A984D48156A271787AB8883F9893D51EC4B563B53");
    let mut encrypted = [0u8; 24];
    let mut engine = DesEngine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();

    for (input, output) in plaintext
        .chunks_exact(BLOCK_BYTES)
        .zip(encrypted.chunks_exact_mut(BLOCK_BYTES))
    {
        engine.process_block(input, output).unwrap();
    }
    assert_eq!(encrypted.as_slice(), ciphertext);

    let mut recovered = [0u8; 24];
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    for (input, output) in ciphertext
        .chunks_exact(BLOCK_BYTES)
        .zip(recovered.chunks_exact_mut(BLOCK_BYTES))
    {
        engine.process_block(input, output).unwrap();
    }
    assert_eq!(&recovered, plaintext);
}
