//! AES vectors from Bouncy Castle's `AesTest.cs` / `AesX86Test.cs`.

use tc_crypto_core::BlockCipher;
use tc_crypto_engines::{AES_BLOCK_BYTES, AesEngine, AesError, AesLightEngine, AesParams};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn run_vector_with<E>(key: &str, plaintext: &str, ciphertext: &str, mut engine: E)
where
    for<'a> E: BlockCipher<Params<'a> = AesParams, Error = AesError>,
{
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = AesParams::new(&key).unwrap();

    engine.init(true, &params).unwrap();
    let mut encrypted = [0u8; AES_BLOCK_BYTES];
    assert_eq!(
        engine.process_block(&plaintext, &mut encrypted).unwrap(),
        16
    );
    assert_eq!(encrypted.as_slice(), ciphertext);

    engine.init(false, &params).unwrap();
    let mut recovered = [0u8; AES_BLOCK_BYTES];
    engine.process_block(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

fn run_vector(key: &str, plaintext: &str, ciphertext: &str) {
    run_vector_with(key, plaintext, ciphertext, AesEngine::new());
    run_vector_with(key, plaintext, ciphertext, AesLightEngine::new());
}

fn run_monte_carlo_with<E>(key: &str, input: &str, expected: &str, mut engine: E)
where
    for<'a> E: BlockCipher<Params<'a> = AesParams, Error = AesError>,
{
    let key = unhex(key);
    let params = AesParams::new(&key).unwrap();
    let mut block: [u8; AES_BLOCK_BYTES] = unhex(input).try_into().unwrap();
    engine.init(true, &params).unwrap();
    for _ in 0..10_000 {
        let mut output = [0u8; AES_BLOCK_BYTES];
        engine.process_block(&block, &mut output).unwrap();
        block = output;
    }
    assert_eq!(block.as_slice(), unhex(expected));
}

fn run_monte_carlo(key: &str, input: &str, expected: &str) {
    run_monte_carlo_with(key, input, expected, AesEngine::new());
    run_monte_carlo_with(key, input, expected, AesLightEngine::new());
}

#[test]
fn bc_single_block_vectors_all_key_sizes() {
    run_vector(
        "80000000000000000000000000000000",
        "00000000000000000000000000000000",
        "0EDD33D3C621E546455BD8BA1418BEC8",
    );
    run_vector(
        "00000000000000000000000000000080",
        "00000000000000000000000000000000",
        "172AEAB3D507678ECAF455C12587ADB7",
    );
    run_vector(
        "000000000000000000000000000000000000000000000000",
        "80000000000000000000000000000000",
        "6CD02513E8D4DC986B4AFE087A60BD0C",
    );
    run_vector(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "80000000000000000000000000000000",
        "DDC6BF790C15760D8D9AEB6F9A75FD4E",
    );
}

#[test]
fn fips_197_appendix_c_vectors() {
    let plaintext = "00112233445566778899AABBCCDDEEFF";
    run_vector(
        "000102030405060708090A0B0C0D0E0F",
        plaintext,
        "69C4E0D86A7B0430D8CDB78070B4C55A",
    );
    run_vector(
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        plaintext,
        "DDA97CA4864CDFE06EAF70A0EC0D7191",
    );
    run_vector(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        plaintext,
        "8EA2B7CA516745BFEAFC49904B496089",
    );
}

#[test]
fn bc_monte_carlo_vectors_all_key_sizes() {
    run_monte_carlo(
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "C34C052CC0DA8D73451AFE5F03BE297F",
    );
    run_monte_carlo(
        "AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114",
        "F3F6752AE8D7831138F041560631B114",
        "77BA00ED5412DFF27C8ED91F3C376172",
    );
    run_monte_carlo(
        "28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386",
        "C737317FE0846F132B23C8C2A672CE22",
        "E58B82BFBA53C0040DC610C642121168",
    );
}
