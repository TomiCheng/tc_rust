//! SEED ECB vectors (RFC 4009) from Bouncy Castle's `SEEDTest.cs`.

use tc_crypto_core::BlockCipher;
use tc_block_cipher::{SeedEngine, SeedParams};

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
    let params = SeedParams::new(&key).unwrap();
    let mut engine = SeedEngine::new();
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
        "000102030405060708090a0b0c0d0e0f",
        "5EBAC6E0054E166819AFF1CC6D346CDB",
    );
    run_vector(
        "000102030405060708090a0b0c0d0e0f",
        "00000000000000000000000000000000",
        "c11f22f20140505084483597e4370f43",
    );
    run_vector(
        "4706480851E61BE85D74BFB3FD956185",
        "83A2F8A288641FB9A4E9A5CC2F131C7D",
        "EE54D13EBCAE706D226BC3142CD40D4A",
    );
    run_vector(
        "28DBC3BC49FFD87DCFA509B11D422BE7",
        "B41E6BE2EBA84A148E2EED84593C5EC7",
        "9B9B7BFCD1813CB95D0B3618F40F5122",
    );
    run_vector(
        "0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E",
        "0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E",
        "8296F2F1B007AB9D533FDEE35A9AD850",
    );
}
