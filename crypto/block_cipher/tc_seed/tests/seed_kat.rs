//! SEED ECB vectors (RFC 4009) from Bouncy Castle's `SEEDTest.cs`.

mod common;

use common::unhex;
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_params::KeyRef;
use tc_seed::{BLOCK_BYTES, SeedEngine};

fn run_vector(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = KeyRef::new(&key);
    let mut engine = SeedEngine::new();

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
fn bc_ecb_vectors() {
    for (key, plaintext, ciphertext) in [
        (
            "00000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f",
            "5EBAC6E0054E166819AFF1CC6D346CDB",
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "00000000000000000000000000000000",
            "c11f22f20140505084483597e4370f43",
        ),
        (
            "4706480851E61BE85D74BFB3FD956185",
            "83A2F8A288641FB9A4E9A5CC2F131C7D",
            "EE54D13EBCAE706D226BC3142CD40D4A",
        ),
        (
            "28DBC3BC49FFD87DCFA509B11D422BE7",
            "B41E6BE2EBA84A148E2EED84593C5EC7",
            "9B9B7BFCD1813CB95D0B3618F40F5122",
        ),
        (
            "0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E",
            "0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E",
            "8296F2F1B007AB9D533FDEE35A9AD850",
        ),
    ] {
        run_vector(key, plaintext, ciphertext);
    }
}
