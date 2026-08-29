//! Camellia vectors from RFC 3713 and Bouncy Castle's `CamelliaTest.cs`.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_block_cipher::{
    CAMELLIA_BLOCK_BYTES, CamelliaEngine, BlockCipherError, CamelliaLightEngine, CamelliaParams,
};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn run_vector_for<E>(create: impl Fn() -> E, key: &[u8], plaintext: &[u8], ciphertext: &[u8])
where
    E: BlockCipher<Error = BlockCipherError>,
    for<'a> E: BlockCipherInit<Params<'a> = CamelliaParams>,
{
    let params = CamelliaParams::new(key).unwrap();
    let mut engine = create();

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = [0u8; CAMELLIA_BLOCK_BYTES];
    assert_eq!(
        engine.process_block(plaintext, &mut encrypted).unwrap(),
        CAMELLIA_BLOCK_BYTES
    );
    assert_eq!(encrypted.as_slice(), ciphertext);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; CAMELLIA_BLOCK_BYTES];
    engine.process_block(ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

fn run_vector(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);

    run_vector_for(CamelliaEngine::new, &key, &plaintext, &ciphertext);
    run_vector_for(CamelliaLightEngine::new, &key, &plaintext, &ciphertext);
}

#[test]
fn bc_and_rfc_3713_vectors_all_key_sizes() {
    for (key, plaintext, ciphertext) in [
        (
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "07923A39EB0A817D1C4D87BDB82D1F1C",
        ),
        (
            "80000000000000000000000000000000",
            "00000000000000000000000000000000",
            "6C227F749319A3AA7DA235A9BBA05A2C",
        ),
        (
            "0123456789abcdeffedcba9876543210",
            "0123456789abcdeffedcba9876543210",
            "67673138549669730857065648eabe43",
        ),
        (
            "0123456789abcdeffedcba98765432100011223344556677",
            "0123456789abcdeffedcba9876543210",
            "b4993401b3e996f84ee5cee7d79b09b9",
        ),
        (
            "000000000000000000000000000000000000000000000000",
            "00040000000000000000000000000000",
            "9BCA6C88B928C1B0F57F99866583A9BC",
        ),
        (
            "949494949494949494949494949494949494949494949494",
            "636EB22D84B006381235641BCF0308D2",
            "94949494949494949494949494949494",
        ),
        (
            "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
            "0123456789abcdeffedcba9876543210",
            "9acc237dff16d76c20ef7c919e3a7509",
        ),
        (
            "4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A",
            "057764FE3A500EDBD988C5C3B56CBA9A",
            "4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A",
        ),
        (
            "0303030303030303030303030303030303030303030303030303030303030303",
            "7968B08ABA92193F2295121EF8D75C8A",
            "03030303030303030303030303030303",
        ),
    ] {
        run_vector(key, plaintext, ciphertext);
    }
}
