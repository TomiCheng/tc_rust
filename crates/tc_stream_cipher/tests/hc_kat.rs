//! Known-answer and behavioral tests for HC-128 and HC-256.
//!
//! The vectors come from Bouncy Castle's `HCFamilyTest` and ECRYPT vector
//! files, which in turn cite the official HC-128 and HC-256 reference papers.

use tc_cipher_core::{StreamCipher, StreamCipherInit};
use tc_stream_cipher::{Hc128Engine, Hc128Params, Hc256Engine, Hc256Params, StreamCipherError};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hc128_keystream(key: &[u8], iv: &[u8], length: usize) -> Vec<u8> {
    let params = Hc128Params::new(key, iv).unwrap();
    let mut engine = Hc128Engine::new();
    engine.init(true, &params).unwrap();
    let mut output = vec![0u8; length];
    assert_eq!(
        engine.process_bytes(&vec![0u8; length], &mut output),
        Ok(length)
    );
    output
}

fn hc256_keystream(key: &[u8], iv: &[u8], length: usize) -> Vec<u8> {
    let params = Hc256Params::new(key, iv).unwrap();
    let mut engine = Hc256Engine::new();
    engine.init(true, &params).unwrap();
    let mut output = vec![0u8; length];
    assert_eq!(
        engine.process_bytes(&vec![0u8; length], &mut output),
        Ok(length)
    );
    output
}

#[test]
fn hc128_official_zero_vector() {
    let expected = hex("82001573A003FD3B7FD72FFB0EAF63AA\
         C62F12DEB629DCA72785A66268EC758B\
         1EDB36900560898178E0AD009ABF1F49\
         1330DC1C246E3D6CB264F6900271D59C");
    assert_eq!(hc128_keystream(&[0u8; 16], &[0u8; 16], 64), expected);
}

#[test]
fn hc128_official_nonzero_vector() {
    let key = hex("0053A6F94C9FF24598EB3E91E4378ADD");
    let iv = hex("0D74DB42A91077DE45AC137AE148AF16");
    let expected = hex("2E1ED12A8551C05AF41FF39D8F9DF933\
         122B5235D48FC2A6F20037E69BDBBCE8\
         05782EFC16C455A4B3FF06142317535E\
         F876104C32445138CB26EBC2F88A684C");
    assert_eq!(hc128_keystream(&key, &iv, 64), expected);
}

#[test]
fn hc256_official_128_bit_key_and_iv_vector() {
    let expected = hex("5B078985D8F6F30D42C5C02FA6B67951\
         53F06534801F89F24E74248B720B4818\
         CD9227ECEBCF4DBF8DBF6977E4AE14FA\
         E8504C7BC8A9F3EA6C0106F5327E6981");
    assert_eq!(hc256_keystream(&[0u8; 16], &[0u8; 16], 64), expected);
}

#[test]
fn hc256_official_256_bit_key_and_iv_vector() {
    let key = hex("0053A6F94C9FF24598EB3E91E4378ADD\
         3083D6297CCF2275C81B6EC11467BA0D");
    let iv = hex("0D74DB42A91077DE45AC137AE148AF16\
         7DE44BB21980E74EB51C83EA51B81F86");
    let expected = hex("23D9E70A45EB0127884D66D9F6F23C01\
         D1F88AFD629270127247256C1FFF91E9\
         1A797BD98ADD23AE15BEE6EEA3CEFDBF\
         A3ED6D22D9C4F459DB10C40CDF4F4DFF");
    assert_eq!(hc256_keystream(&key, &iv, 64), expected);
}

#[test]
fn hc256_matches_all_bc_key_and_iv_size_combinations() {
    let key_128 = hex("80000000000000000000000000000000");
    let mut key_256 = key_128.clone();
    key_256.extend_from_slice(&[0u8; 16]);
    let iv_128 = [0u8; 16];
    let iv_256 = [0u8; 32];

    let expected_128_key = hex("F1B055D7BF34DE7E524D23B5556B743A\
         EAF06AE9076FD2F48389039C4B24C38D\
         DFC3AC63A148755FB3CF0CB8FB1EDEEA\
         63CD484036FFAC3F5F99FC7A10335060");
    assert_eq!(hc256_keystream(&key_128, &iv_128, 64), expected_128_key);
    assert_eq!(hc256_keystream(&key_128, &iv_256, 64), expected_128_key);

    let expected_256_key = hex("240146C5EA6C72A8DFC93E54E8811C32\
         A85E0BF7291BDDC0DBEAE086D051D5B0\
         5CC9DD5C311ED2F7E8484CC477C68BC8\
         C5D3F3450553F5327253768E958C0C55");
    assert_eq!(hc256_keystream(&key_256, &iv_128, 64), expected_256_key);
    assert_eq!(hc256_keystream(&key_256, &iv_256, 64), expected_256_key);
}

#[test]
fn hc128_reset_chunking_and_single_byte_processing_match() {
    let params = Hc128Params::new(&[0x11; 16], &[0x22; 16]).unwrap();
    let input = [0x5au8; 97];

    let mut engine = Hc128Engine::new();
    assert_eq!(engine.algorithm_name(), "HC-128");
    engine.init(true, &params).unwrap();
    let mut bulk = [0u8; 97];
    engine.process_bytes(&input, &mut bulk).unwrap();

    engine.reset();
    let mut chunked = [0u8; 97];
    engine
        .process_bytes(&input[..13], &mut chunked[..13])
        .unwrap();
    engine
        .process_bytes(&input[13..], &mut chunked[13..])
        .unwrap();
    assert_eq!(chunked, bulk);

    engine.reset();
    let single: Vec<u8> = input
        .iter()
        .map(|&byte| engine.return_byte(byte).unwrap())
        .collect();
    assert_eq!(single, bulk);
}

#[test]
fn hc256_reset_chunking_and_single_byte_processing_match() {
    let params = Hc256Params::new(&[0x11; 32], &[0x22; 32]).unwrap();
    let input = [0x5au8; 97];

    let mut engine = Hc256Engine::new();
    assert_eq!(engine.algorithm_name(), "HC-256");
    engine.init(true, &params).unwrap();
    let mut bulk = [0u8; 97];
    engine.process_bytes(&input, &mut bulk).unwrap();

    engine.reset();
    let mut chunked = [0u8; 97];
    engine
        .process_bytes(&input[..13], &mut chunked[..13])
        .unwrap();
    engine
        .process_bytes(&input[13..], &mut chunked[13..])
        .unwrap();
    assert_eq!(chunked, bulk);

    engine.reset();
    let single: Vec<u8> = input
        .iter()
        .map(|&byte| engine.return_byte(byte).unwrap())
        .collect();
    assert_eq!(single, bulk);
}

#[test]
fn hc_family_encrypt_decrypt_round_trips() {
    let plaintext = b"HC stream ciphers use the same operation in both directions";

    let params128 = Hc128Params::new(&[0x11; 16], &[0x22; 16]).unwrap();
    let mut hc128 = Hc128Engine::new();
    hc128.init(true, &params128).unwrap();
    let mut ciphertext128 = vec![0u8; plaintext.len()];
    hc128.process_bytes(plaintext, &mut ciphertext128).unwrap();
    hc128.init(false, &params128).unwrap();
    let mut recovered128 = vec![0u8; plaintext.len()];
    hc128
        .process_bytes(&ciphertext128, &mut recovered128)
        .unwrap();
    assert_eq!(recovered128, plaintext);

    let params256 = Hc256Params::new(&[0x33; 32], &[0x44; 32]).unwrap();
    let mut hc256 = Hc256Engine::new();
    hc256.init(true, &params256).unwrap();
    let mut ciphertext256 = vec![0u8; plaintext.len()];
    hc256.process_bytes(plaintext, &mut ciphertext256).unwrap();
    hc256.init(false, &params256).unwrap();
    let mut recovered256 = vec![0u8; plaintext.len()];
    hc256
        .process_bytes(&ciphertext256, &mut recovered256)
        .unwrap();
    assert_eq!(recovered256, plaintext);
}

#[test]
fn hc128_validates_parameters_and_runtime_state() {
    assert_eq!(
        Hc128Params::new(&[0u8; 15], &[0u8; 16]).unwrap_err(),
        StreamCipherError::InvalidKeyLength(15)
    );
    assert_eq!(
        Hc128Params::new(&[0u8; 16], &[0u8; 15]).unwrap_err(),
        StreamCipherError::InvalidIvLength(15)
    );

    let params = Hc128Params::new(&[0u8; 16], &[0u8; 16]).unwrap();
    assert!(!format!("{params:?}").contains("000000"));

    let mut engine = Hc128Engine::new();
    assert_eq!(
        engine.return_byte(0),
        Err(StreamCipherError::NotInitialised)
    );
    engine.init(true, &params).unwrap();
    assert_eq!(
        engine.process_bytes(&[0u8; 2], &mut [0u8; 1]),
        Err(StreamCipherError::OutputBufferTooShort)
    );
}

#[test]
fn hc256_validates_parameters_and_runtime_state() {
    assert_eq!(
        Hc256Params::new(&[0u8; 15], &[0u8; 16]).unwrap_err(),
        StreamCipherError::InvalidKeyLength(15)
    );
    assert_eq!(
        Hc256Params::new(&[0u8; 16], &[0u8; 15]).unwrap_err(),
        StreamCipherError::InvalidIvLength(15)
    );

    let params = Hc256Params::new(&[0u8; 16], &[0u8; 17]).unwrap();
    assert!(!format!("{params:?}").contains("000000"));

    let mut engine = Hc256Engine::new();
    assert_eq!(
        engine.return_byte(0),
        Err(StreamCipherError::NotInitialised)
    );
    engine.init(true, &params).unwrap();
    assert_eq!(
        engine.process_bytes(&[0u8; 2], &mut [0u8; 1]),
        Err(StreamCipherError::OutputBufferTooShort)
    );
}

#[test]
fn hc256_ignores_iv_bytes_after_the_first_32_like_bc() {
    let key = [0x42u8; 32];
    let iv_32 = [0x24u8; 32];
    let mut iv_48 = [0x24u8; 48];
    iv_48[32..].fill(0xff);

    assert_eq!(
        hc256_keystream(&key, &iv_32, 64),
        hc256_keystream(&key, &iv_48, 64)
    );
}
