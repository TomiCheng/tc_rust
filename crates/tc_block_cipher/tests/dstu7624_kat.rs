//! DSTU 7624 ECB vectors from Bouncy Castle's `DSTU7624Test.cs`.
//!
//! One vector per valid block/key combination. The widths are compile-time
//! word counts, so each vector names its own instantiation rather than passing
//! a block size at run time.

use tc_block_cipher::dstu7624::{Dstu7624Config, ValidDstu7624Config};
use tc_block_cipher::{Dstu7624Engine, Dstu7624Params};
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn run_vector<const BLOCK_WORDS: usize, const KEY_WORDS: usize>(
    key: &str,
    plaintext: &str,
    ciphertext: &str,
) where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let bytes = BLOCK_WORDS * 8;
    let params = Dstu7624Params::<KEY_WORDS>::new(&key).unwrap();
    let mut engine = Dstu7624Engine::<BLOCK_WORDS, KEY_WORDS>::new();
    let mut output = vec![0u8; bytes];

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(engine.process_block(&plaintext, &mut output).unwrap(), bytes);
    assert_eq!(output, ciphertext, "encrypt {}-bit block", bytes * 8);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(output, plaintext, "decrypt {}-bit block", bytes * 8);
}

#[test]
fn bc_ecb_vector_128_block_128_key() {
    run_vector::<2, 2>(
        "000102030405060708090A0B0C0D0E0F",
        "101112131415161718191A1B1C1D1E1F",
        "81BF1C7D779BAC20E1C9EA39B4D2AD06",
    );
}

#[test]
fn bc_ecb_vector_128_block_256_key() {
    run_vector::<2, 4>(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "202122232425262728292A2B2C2D2E2F",
        "58EC3E091000158A1148F7166F334F14",
    );
}

#[test]
fn bc_ecb_vector_256_block_256_key() {
    run_vector::<4, 4>(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C",
    );
}

#[test]
fn bc_ecb_vector_256_block_512_key() {
    run_vector::<4, 8>(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        "606990E9E6B7B67A4BD6D893D72268B78E02C83C3CD7E102FD2E74A8FDFE5DD9",
    );
}

#[test]
fn bc_ecb_vector_512_block_512_key() {
    run_vector::<8, 8>(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
        "4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B895D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9",
    );
}
