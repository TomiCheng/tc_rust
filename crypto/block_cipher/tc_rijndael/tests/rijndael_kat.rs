//! Rijndael vectors from Bouncy Castle's `RijndaelTest.cs`.

mod common;

use common::unhex;
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_params::KeyRef;
use tc_rijndael::RijndaelEngine;

fn assert_vector<const BLOCK_COLUMNS: usize>(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let block_bytes = BLOCK_COLUMNS * 4;
    let mut engine = RijndaelEngine::<BLOCK_COLUMNS>::new();
    let mut output = vec![0u8; block_bytes];

    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&key))
        .unwrap();
    assert_eq!(
        engine.process_block(&plaintext, &mut output).unwrap(),
        block_bytes
    );
    assert_eq!(output, ciphertext);

    engine
        .init(CipherDirection::Decrypt, &KeyRef::new(&key))
        .unwrap();
    engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(output, plaintext);
}

fn assert_monte_carlo(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let mut engine = RijndaelEngine::<4>::new();
    let mut block = plaintext.clone();
    let mut output = vec![0u8; block.len()];

    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&key))
        .unwrap();
    for _ in 0..10_000 {
        engine.process_block(&block, &mut output).unwrap();
        block.copy_from_slice(&output);
    }
    assert_eq!(block, ciphertext);

    engine
        .init(CipherDirection::Decrypt, &KeyRef::new(&key))
        .unwrap();
    for _ in 0..10_000 {
        engine.process_block(&block, &mut output).unwrap();
        block.copy_from_slice(&output);
    }
    assert_eq!(block, plaintext);
}

#[test]
fn bc_monte_carlo_128_block() {
    assert_monte_carlo(
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "c34c052cc0da8d73451afe5f03be297f",
    );
    assert_monte_carlo(
        "5f060d3716b345c253f6749abac10917",
        "355f697e8b868b65b25a04e18d782afa",
        "acc863637868e3e068d2fd6e3508454a",
    );
    assert_monte_carlo(
        "aafe47ee82411a2bf3f6752ae8d7831138f041560631b114",
        "f3f6752ae8d7831138f041560631b114",
        "77ba00ed5412dff27c8ed91f3c376172",
    );
    assert_monte_carlo(
        "28e79e2afc5f7745fccabe2f6257c2ef4c4edfb37324814ed4137c288711a386",
        "c737317fe0846f132b23c8c2a672ce22",
        "e58b82bfba53c0040dc610c642121168",
    );
}

#[test]
fn bc_ecb_vectors_128_block() {
    assert_vector::<4>(
        "80000000000000000000000000000000",
        "00000000000000000000000000000000",
        "0edd33d3c621e546455bd8ba1418bec8",
    );
    assert_vector::<4>(
        "00000000000000000000000000000080",
        "00000000000000000000000000000000",
        "172aeab3d507678ecaf455c12587adb7",
    );
    assert_vector::<4>(
        "000000000000000000000000000000000000000000000000",
        "80000000000000000000000000000000",
        "6cd02513e8d4dc986b4afe087a60bd0c",
    );
    assert_vector::<4>(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "80000000000000000000000000000000",
        "ddc6bf790c15760d8d9aeb6f9a75fd4e",
    );
}

#[test]
fn bc_ecb_vectors_160_block() {
    let plaintext = "3243f6a8885a308d313198a2e03707344a409382";
    for (key, ciphertext) in [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "16e73aec921314c29df905432bc8968ab64b1f51",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160",
            "0553eb691670dd8a5a5b5addf1aa7450f7a0e587",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5",
            "73cd6f3423036790463aa9e19cfcde894ea16623",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90",
            "601b5dcd1cf4ece954c740445340bf0afdc048df",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
            "579e930b36c1529aa3e86628bacfe146942882cf",
        ),
    ] {
        assert_vector::<5>(key, plaintext, ciphertext);
    }
}

#[test]
fn bc_ecb_vectors_192_block() {
    let plaintext = "3243f6a8885a308d313198a2e03707344a4093822299f31d";
    for (key, ciphertext) in [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "b24d275489e82bb8f7375e0d5fcdb1f481757c538b65148a",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5",
            "725ae43b5f3161de806a7c93e0bca93c967ec1ae1b71e1cf",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90",
            "bbfc14180afbf6a36382a061843f0b63e769acdc98769130",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
            "0ebacf199e3315c2e34b24fcc7c46ef4388aa475d66c194c",
        ),
    ] {
        assert_vector::<6>(key, plaintext, ciphertext);
    }
}

#[test]
fn bc_ecb_vectors_224_block() {
    let plaintext = "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9";
    for (key, ciphertext) in [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "b0a8f78f6b3c66213f792ffd2a61631f79331407a5e5c8d3793aceb1",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160",
            "08b99944edfce33a2acb131183ab0168446b2d15e958480010f545e3",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5",
            "be4c597d8f7efe22a2f7e5b1938e2564d452a5bfe72399c7af1101e2",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90",
            "ef529598ecbce297811b49bbed2c33bbe1241d6e1a833dbe119569e8",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
            "02fafc200176ed05deb8edb82a3555b0b10d47a388dfd59cab2f6c11",
        ),
    ] {
        assert_vector::<7>(key, plaintext, ciphertext);
    }
}

#[test]
fn bc_ecb_vectors_256_block() {
    let plaintext = "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8";
    for (key, ciphertext) in [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "7d15479076b69a46ffb3b3beae97ad8313f622f67fedb487de9f06b9ed9c8f19",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160",
            "514f93fb296b5ad16aa7df8b577abcbd484decacccc7fb1f18dc567309ceeffd",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5",
            "5d7101727bb25781bf6715b0e6955282b9610e23a43c2eb062699f0ebf5887b2",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90",
            "d56c5a63627432579e1dd308b2c8f157b40a4bfb56fea1377b25d3ed3d6dbf80",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
            "a49406115dfb30a40418aafa4869b7c6a886ff31602a7dd19c889dc64f7e4e7a",
        ),
    ] {
        assert_vector::<8>(key, plaintext, ciphertext);
    }
}
