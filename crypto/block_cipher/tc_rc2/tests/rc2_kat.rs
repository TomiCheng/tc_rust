//! RC2 vectors from Bouncy Castle's `RC2Test.cs` and RFC 2268.

mod common;

use common::unhex;
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_rc2::{BLOCK_BYTES, Params, Rc2Engine};

fn assert_vector(key: &str, effective_key_bits: usize, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = Params::with_effective_key_bits(&key, effective_key_bits);
    let mut engine = Rc2Engine::new();
    let mut output = [0u8; BLOCK_BYTES];

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(
        engine.process_block(&plaintext, &mut output).unwrap(),
        BLOCK_BYTES
    );
    assert_eq!(output.as_slice(), ciphertext);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(output.as_slice(), plaintext);
}

#[test]
fn bc_ecb_vectors() {
    assert_vector(
        "0000000000000000",
        63,
        "0000000000000000",
        "ebb773f993278eff",
    );
    assert_vector(
        "ffffffffffffffff",
        64,
        "ffffffffffffffff",
        "278b27e42e2f0d49",
    );
    assert_vector(
        "3000000000000000",
        64,
        "1000000000000001",
        "30649edf9be7d2c2",
    );
    assert_vector("88", 64, "0000000000000000", "61a8a244adacccf0");
    assert_vector("88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f");
    assert_vector(
        "88bca90e90875a7f0f79c384627bafb2",
        64,
        "0000000000000000",
        "1a807d272bbe5db1",
    );
    assert_vector(
        "88bca90e90875a7f0f79c384627bafb2",
        128,
        "0000000000000000",
        "2269552ab0f85ca6",
    );
    assert_vector(
        "88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e",
        129,
        "0000000000000000",
        "5b78d3a43dfff1f1",
    );
}
