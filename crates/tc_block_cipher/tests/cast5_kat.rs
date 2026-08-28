//! CAST5 vectors from RFC 2144 and Bouncy Castle's `Cast5Test.cs`.

use tc_crypto_core::BlockCipher;
use tc_block_cipher::{CAST5_BLOCK_BYTES, Cast5Engine, Cast5Params};

fn unhex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    core::array::from_fn(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap())
}

#[test]
fn rfc_2144_all_round_counts() {
    let plaintext = unhex::<CAST5_BLOCK_BYTES>("0123456789ABCDEF");
    for (key, ciphertext) in [
        (
            &unhex::<16>("0123456712345678234567893456789A")[..],
            unhex::<CAST5_BLOCK_BYTES>("238B4FE5847E44B2"),
        ),
        (
            &unhex::<10>("01234567123456782345")[..],
            unhex::<CAST5_BLOCK_BYTES>("EB6A711A2C02271B"),
        ),
        (
            &unhex::<5>("0123456712")[..],
            unhex::<CAST5_BLOCK_BYTES>("7AC816D16E9B302E"),
        ),
    ] {
        let params = Cast5Params::new(key).unwrap();
        let mut engine = Cast5Engine::new();

        engine.init(true, &params).unwrap();
        let mut encrypted = [0u8; CAST5_BLOCK_BYTES];
        engine.process_block(&plaintext, &mut encrypted).unwrap();
        assert_eq!(encrypted, ciphertext);

        engine.init(false, &params).unwrap();
        let mut recovered = [0u8; CAST5_BLOCK_BYTES];
        engine.process_block(&ciphertext, &mut recovered).unwrap();
        assert_eq!(recovered, plaintext);
    }
}

#[test]
fn reinitialising_switches_between_reduced_and_full_rounds() {
    let plaintext = unhex::<CAST5_BLOCK_BYTES>("0123456789ABCDEF");
    let short_key = unhex::<10>("01234567123456782345");
    let long_key = unhex::<16>("0123456712345678234567893456789A");
    let mut engine = Cast5Engine::new();

    engine
        .init(true, &Cast5Params::new(&short_key).unwrap())
        .unwrap();
    engine
        .init(true, &Cast5Params::new(&long_key).unwrap())
        .unwrap();

    let mut encrypted = [0u8; CAST5_BLOCK_BYTES];
    engine.process_block(&plaintext, &mut encrypted).unwrap();
    assert_eq!(encrypted, unhex::<CAST5_BLOCK_BYTES>("238B4FE5847E44B2"));
}
