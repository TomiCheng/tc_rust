//! CAST6 vectors from RFC 2612 and Bouncy Castle's `CAST6Test.cs`.

use tc_crypto_core::BlockCipher;
use tc_crypto_engines::{CAST6_BLOCK_BYTES, Cast6Engine, Cast6Params};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn rfc_2612_vectors() {
    let plaintext = [0u8; CAST6_BLOCK_BYTES];
    for (key, ciphertext) in [
        (
            "2342bb9efa38542c0af75647f29f615d",
            "c842a08972b43d20836c91d1b7530f6b",
        ),
        (
            "2342bb9efa38542cbed0ac83940ac298bac77a7717942863",
            "1b386c0210dcadcbdd0e41aa08a7a7e8",
        ),
        (
            "2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604",
            "4f6a2038286897b9c9870136553317fa",
        ),
    ] {
        let key = unhex(key);
        let ciphertext = unhex(ciphertext);
        let params = Cast6Params::new(&key).unwrap();
        let mut engine = Cast6Engine::new();

        engine.init(true, &params).unwrap();
        let mut encrypted = [0u8; CAST6_BLOCK_BYTES];
        engine.process_block(&plaintext, &mut encrypted).unwrap();
        assert_eq!(encrypted.as_slice(), ciphertext);

        engine.init(false, &params).unwrap();
        let mut recovered = [0u8; CAST6_BLOCK_BYTES];
        engine.process_block(&ciphertext, &mut recovered).unwrap();
        assert_eq!(recovered, plaintext);
    }
}

#[test]
fn all_standard_key_sizes_round_trip() {
    let plaintext = core::array::from_fn(|index| (index as u8).wrapping_mul(0x17));

    for key_len in [16, 20, 24, 28, 32] {
        let key: Vec<u8> = (0..key_len)
            .map(|index| (index as u8).wrapping_mul(0x3d).wrapping_add(0x29))
            .collect();
        let params = Cast6Params::new(&key).unwrap();
        let mut engine = Cast6Engine::new();
        let mut ciphertext = [0u8; CAST6_BLOCK_BYTES];
        let mut recovered = [0u8; CAST6_BLOCK_BYTES];

        engine.init(true, &params).unwrap();
        engine.process_block(&plaintext, &mut ciphertext).unwrap();
        engine.init(false, &params).unwrap();
        engine.process_block(&ciphertext, &mut recovered).unwrap();
        assert_eq!(recovered, plaintext);
    }
}
