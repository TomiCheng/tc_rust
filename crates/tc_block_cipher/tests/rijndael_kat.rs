//! Rijndael ECB vectors (NIST / Gladman) from Bouncy Castle's `RijndaelTest.cs`.

use tc_crypto_core::BlockCipher;
use tc_block_cipher::{RijndaelEngine, RijndaelParams};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn run_vector(block_bits: usize, key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let bytes = block_bits / 8;
    let params = RijndaelParams::new(&key).unwrap();
    let mut engine = RijndaelEngine::new(block_bits).unwrap();
    let mut output = vec![0u8; bytes];

    engine.init(true, &params).unwrap();
    assert_eq!(engine.process_block(&plaintext, &mut output).unwrap(), bytes);
    assert_eq!(output, ciphertext, "encrypt {block_bits}-bit block");

    engine.init(false, &params).unwrap();
    engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(output, plaintext, "decrypt {block_bits}-bit block");
}

/// Encrypts one block in place `iterations` times (chaining output back to
/// input), checks the result, then decrypts the same number of times.
fn run_monte_carlo(iterations: usize, key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = RijndaelParams::new(&key).unwrap();
    let mut engine = RijndaelEngine::new(128).unwrap();

    let mut buf = plaintext.clone();
    let mut tmp = vec![0u8; buf.len()];

    engine.init(true, &params).unwrap();
    for _ in 0..iterations {
        engine.process_block(&buf, &mut tmp).unwrap();
        buf.copy_from_slice(&tmp);
    }
    assert_eq!(buf, ciphertext, "monte carlo encrypt");

    engine.init(false, &params).unwrap();
    for _ in 0..iterations {
        engine.process_block(&buf, &mut tmp).unwrap();
        buf.copy_from_slice(&tmp);
    }
    assert_eq!(buf, plaintext, "monte carlo decrypt");
}

#[test]
fn bc_monte_carlo_128_block() {
    run_monte_carlo(
        10000,
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "C34C052CC0DA8D73451AFE5F03BE297F",
    );
    run_monte_carlo(
        10000,
        "5F060D3716B345C253F6749ABAC10917",
        "355F697E8B868B65B25A04E18D782AFA",
        "ACC863637868E3E068D2FD6E3508454A",
    );
    run_monte_carlo(
        10000,
        "AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114",
        "F3F6752AE8D7831138F041560631B114",
        "77BA00ED5412DFF27C8ED91F3C376172",
    );
    run_monte_carlo(
        10000,
        "28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386",
        "C737317FE0846F132B23C8C2A672CE22",
        "E58B82BFBA53C0040DC610C642121168",
    );
}

#[test]
fn bc_ecb_vectors_128_block() {
    run_vector(
        128,
        "80000000000000000000000000000000",
        "00000000000000000000000000000000",
        "0EDD33D3C621E546455BD8BA1418BEC8",
    );
    run_vector(
        128,
        "00000000000000000000000000000080",
        "00000000000000000000000000000000",
        "172AEAB3D507678ECAF455C12587ADB7",
    );
    run_vector(
        128,
        "000000000000000000000000000000000000000000000000",
        "80000000000000000000000000000000",
        "6CD02513E8D4DC986B4AFE087A60BD0C",
    );
    run_vector(
        128,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "80000000000000000000000000000000",
        "DDC6BF790C15760D8D9AEB6F9A75FD4E",
    );
}

#[test]
fn bc_ecb_vectors_160_block() {
    let pt = "3243f6a8885a308d313198a2e03707344a409382";
    run_vector(160, "2b7e151628aed2a6abf7158809cf4f3c", pt, "16e73aec921314c29df905432bc8968ab64b1f51");
    run_vector(160, "2b7e151628aed2a6abf7158809cf4f3c762e7160", pt, "0553eb691670dd8a5a5b5addf1aa7450f7a0e587");
    run_vector(160, "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5", pt, "73cd6f3423036790463aa9e19cfcde894ea16623");
    run_vector(160, "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90", pt, "601b5dcd1cf4ece954c740445340bf0afdc048df");
    run_vector(160, "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe", pt, "579e930b36c1529aa3e86628bacfe146942882cf");
}

#[test]
fn bc_ecb_vectors_192_block() {
    let pt = "3243f6a8885a308d313198a2e03707344a4093822299f31d";
    run_vector(192, "2b7e151628aed2a6abf7158809cf4f3c", pt, "b24d275489e82bb8f7375e0d5fcdb1f481757c538b65148a");
    run_vector(192, "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5", pt, "725ae43b5f3161de806a7c93e0bca93c967ec1ae1b71e1cf");
    run_vector(192, "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90", pt, "bbfc14180afbf6a36382a061843f0b63e769acdc98769130");
    run_vector(192, "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe", pt, "0ebacf199e3315c2e34b24fcc7c46ef4388aa475d66c194c");
}

#[test]
fn bc_ecb_vectors_224_block() {
    let pt = "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9";
    run_vector(224, "2b7e151628aed2a6abf7158809cf4f3c", pt, "b0a8f78f6b3c66213f792ffd2a61631f79331407a5e5c8d3793aceb1");
    run_vector(224, "2b7e151628aed2a6abf7158809cf4f3c762e7160", pt, "08b99944edfce33a2acb131183ab0168446b2d15e958480010f545e3");
    run_vector(224, "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5", pt, "be4c597d8f7efe22a2f7e5b1938e2564d452a5bfe72399c7af1101e2");
    run_vector(224, "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90", pt, "ef529598ecbce297811b49bbed2c33bbe1241d6e1a833dbe119569e8");
    run_vector(224, "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe", pt, "02fafc200176ed05deb8edb82a3555b0b10d47a388dfd59cab2f6c11");
}

#[test]
fn bc_ecb_vectors_256_block() {
    let pt = "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8";
    run_vector(256, "2b7e151628aed2a6abf7158809cf4f3c", pt, "7d15479076b69a46ffb3b3beae97ad8313f622f67fedb487de9f06b9ed9c8f19");
    run_vector(256, "2b7e151628aed2a6abf7158809cf4f3c762e7160", pt, "514f93fb296b5ad16aa7df8b577abcbd484decacccc7fb1f18dc567309ceeffd");
    run_vector(256, "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5", pt, "5d7101727bb25781bf6715b0e6955282b9610e23a43c2eb062699f0ebf5887b2");
    run_vector(256, "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90", pt, "d56c5a63627432579e1dd308b2c8f157b40a4bfb56fea1377b25d3ed3d6dbf80");
    run_vector(256, "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe", pt, "a49406115dfb30a40418aafa4869b7c6a886ff31602a7dd19c889dc64f7e4e7a");
}
