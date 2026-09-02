//! AES vectors from FIPS 197 appendix C and Bouncy Castle's `AesTest.cs`.
//!
//! Every vector runs through both engines, since they are offered as
//! interchangeable implementations of the same cipher.

mod common;

use common::unhex;
use tc_aes::{AesEngine, AesLightEngine, BLOCK_BYTES};
use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_params::{KeyParams, KeyRef};

/// Any engine in this crate: initialised from borrowed key bytes, then run one
/// block at a time.
trait AesImplementation:
    BlockCipher<Error = BlockError> + for<'a> BlockCipherInit<dyn KeyParams + 'a, Error = InitError>
{
}

impl<E> AesImplementation for E where
    E: BlockCipher<Error = BlockError>
        + for<'a> BlockCipherInit<dyn KeyParams + 'a, Error = InitError>
{
}

fn run_vector_with<E: AesImplementation>(
    mut engine: E,
    key: &str,
    plaintext: &str,
    ciphertext: &str,
) {
    let key_bytes = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = KeyRef::new(&key_bytes);

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = [0u8; BLOCK_BYTES];
    assert_eq!(
        engine.process_block(&plaintext, &mut encrypted).unwrap(),
        BLOCK_BYTES
    );
    assert_eq!(encrypted.as_slice(), ciphertext, "key {key}");

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; BLOCK_BYTES];
    engine.process_block(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered.as_slice(), plaintext, "key {key}");
}

fn run_vector(key: &str, plaintext: &str, ciphertext: &str) {
    run_vector_with(AesEngine::new(), key, plaintext, ciphertext);
    run_vector_with(AesLightEngine::new(), key, plaintext, ciphertext);
}

/// Feeds each block back in ten thousand times, as Bouncy Castle does.
fn run_monte_carlo_with<E: AesImplementation>(
    mut engine: E,
    key: &str,
    input: &str,
    expected: &str,
) {
    let key_bytes = unhex(key);
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&key_bytes))
        .unwrap();

    let mut block: [u8; BLOCK_BYTES] = unhex(input).try_into().unwrap();
    let mut output = [0u8; BLOCK_BYTES];
    for _ in 0..10_000 {
        engine.process_block(&block, &mut output).unwrap();
        block = output;
    }
    assert_eq!(block.as_slice(), unhex(expected), "key {key}");
}

fn run_monte_carlo(key: &str, input: &str, expected: &str) {
    run_monte_carlo_with(AesEngine::new(), key, input, expected);
    run_monte_carlo_with(AesLightEngine::new(), key, input, expected);
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
