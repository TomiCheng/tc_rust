//! RC2 ECB vectors (RFC 2268) from Bouncy Castle's `RC2Test.cs`.

use tc_block_cipher::{BlockCipherError, Rc2Engine, Rc2Params};
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn run_vector(key: &str, effective_bits: usize, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = Rc2Params::with_effective_key_bits(&key, effective_bits).unwrap();
    let mut engine = Rc2Engine::new();
    let mut output = vec![0u8; 8];

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(engine.process_block(&plaintext, &mut output).unwrap(), 8);
    assert_eq!(output, ciphertext);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(output, plaintext);
}

#[test]
fn initialized_engine_supports_dynamic_dispatch() {
    let params = Rc2Params::with_effective_key_bits(&[0u8; 8], 63).unwrap();
    let mut engine = Rc2Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();

    let mut cipher: Box<dyn BlockCipher<Error = BlockCipherError>> = Box::new(engine);
    let mut output = [0u8; 8];

    assert_eq!(cipher.algorithm_name(), "RC2");
    assert_eq!(cipher.block_size(), 8);
    assert_eq!(cipher.process_block(&[0u8; 8], &mut output), Ok(8));
    assert_eq!(output, [0xeb, 0xb7, 0x73, 0xf9, 0x93, 0x27, 0x8e, 0xff]);
}

#[test]
fn bc_ecb_vectors() {
    run_vector(
        "0000000000000000",
        63,
        "0000000000000000",
        "ebb773f993278eff",
    );
    run_vector(
        "ffffffffffffffff",
        64,
        "ffffffffffffffff",
        "278b27e42e2f0d49",
    );
    run_vector(
        "3000000000000000",
        64,
        "1000000000000001",
        "30649edf9be7d2c2",
    );
    run_vector("88", 64, "0000000000000000", "61a8a244adacccf0");
    run_vector("88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f");
    run_vector(
        "88bca90e90875a7f0f79c384627bafb2",
        64,
        "0000000000000000",
        "1a807d272bbe5db1",
    );
    run_vector(
        "88bca90e90875a7f0f79c384627bafb2",
        128,
        "0000000000000000",
        "2269552ab0f85ca6",
    );
    run_vector(
        "88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e",
        129,
        "0000000000000000",
        "5b78d3a43dfff1f1",
    );
}
