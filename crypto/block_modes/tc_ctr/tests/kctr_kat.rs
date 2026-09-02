mod common;

use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeError, CipherDirection, StreamCipher,
    StreamCipherInit,
};
use tc_crypto::AlgorithmName;
use tc_ctr::{FixedKctrBlockCipher, KctrBlockCipher};
use tc_dstu7624::Engine128;

use common::{KeyIv, unhex};

const KEY: &str = "000102030405060708090A0B0C0D0E0F";
const IV: &str = "101112131415161718191A1B1C1D1E1F";
const UNALIGNED_IN: &str =
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748";
const UNALIGNED_OUT: &str =
    "A90A6B9780ABDFDFF64D14F5439E88F266DC50EDD341528DD5E698E2F000CE21F872DAF9FE1811844A";
const ALIGNED_IN: &str = "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F";
const ALIGNED_OUT: &str = "B91A7B8790BBCFCFE65D04E5538E98E216AC209DA33122FDA596E8928070BE51";

#[test]
fn dynamic_and_fixed_match_bouncy_castle_stream_vectors() {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let params = KeyIv { key: &key, iv: &iv };
    let input = unhex(UNALIGNED_IN);
    let expected = unhex(UNALIGNED_OUT);

    let mut dynamic = KctrBlockCipher::new(Engine128::new());
    StreamCipherInit::init(&mut dynamic, CipherDirection::Encrypt, &params).unwrap();
    let mut output = vec![0; input.len()];
    dynamic.process_bytes(&input, &mut output).unwrap();
    assert_eq!(output, expected);

    let mut fixed = FixedKctrBlockCipher::<Engine128, 16>::new(Engine128::new());
    StreamCipherInit::init(&mut fixed, CipherDirection::Decrypt, &params).unwrap();
    let mut output = vec![0; input.len()];
    fixed.process_bytes(&input, &mut output).unwrap();
    assert_eq!(output, expected);
}

#[test]
fn block_interface_matches_bouncy_castle_vector() {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let params = KeyIv { key: &key, iv: &iv };
    let input = unhex(ALIGNED_IN);
    let expected = unhex(ALIGNED_OUT);
    let mut mode = KctrBlockCipher::new(Engine128::new());
    BlockCipherInit::init(&mut mode, CipherDirection::Encrypt, &params).unwrap();

    let block_size = BlockCipher::block_size(&mode);
    let mut output = vec![0; input.len()];
    for (input, output) in input.chunks(block_size).zip(output.chunks_mut(block_size)) {
        mode.process_block(input, output).unwrap();
    }
    assert_eq!(output, expected);
}

#[test]
fn reset_restarts_the_keystream_and_reports_name() {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let params = KeyIv { key: &key, iv: &iv };
    let input = unhex(ALIGNED_IN);
    let mut mode = KctrBlockCipher::new(Engine128::new());
    StreamCipherInit::init(&mut mode, CipherDirection::Encrypt, &params).unwrap();

    let mut first = vec![0; input.len()];
    mode.process_bytes(&input, &mut first).unwrap();
    StreamCipher::reset(&mut mode);
    let mut second = vec![0; input.len()];
    mode.process_bytes(&input, &mut second).unwrap();
    assert_eq!(first, second);

    let mut name = String::new();
    mode.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "DSTU7624/KCTR");
    assert!(mode.is_partial_block_okay());
}

#[test]
fn return_byte_matches_process_bytes() {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let params = KeyIv { key: &key, iv: &iv };
    let input = unhex(ALIGNED_IN);

    let mut bulk = KctrBlockCipher::new(Engine128::new());
    StreamCipherInit::init(&mut bulk, CipherDirection::Encrypt, &params).unwrap();
    let mut bulk_output = vec![0; input.len()];
    bulk.process_bytes(&input, &mut bulk_output).unwrap();

    let mut bytewise = KctrBlockCipher::new(Engine128::new());
    StreamCipherInit::init(&mut bytewise, CipherDirection::Encrypt, &params).unwrap();
    let bytewise_output: Vec<u8> = input
        .iter()
        .map(|&byte| bytewise.return_byte(byte).unwrap())
        .collect();

    assert_eq!(bytewise_output, bulk_output);
}

#[test]
fn round_trips_and_rejects_use_before_init() {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let params = KeyIv { key: &key, iv: &iv };
    let plaintext = unhex(ALIGNED_IN);

    let mut encrypt = KctrBlockCipher::new(Engine128::new());
    StreamCipherInit::init(&mut encrypt, CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0; plaintext.len()];
    encrypt
        .process_bytes(&plaintext, &mut ciphertext)
        .unwrap();

    let mut decrypt = KctrBlockCipher::new(Engine128::new());
    StreamCipherInit::init(&mut decrypt, CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = vec![0; ciphertext.len()];
    decrypt
        .process_bytes(&ciphertext, &mut recovered)
        .unwrap();
    assert_eq!(recovered, plaintext);

    let mut uninitialised = KctrBlockCipher::new(Engine128::new());
    let mut output = [0; 1];
    assert!(matches!(
        uninitialised.process_bytes(&[0], &mut output),
        Err(BlockModeError::NotInitialised)
    ));
    assert!(matches!(
        uninitialised.return_byte(0),
        Err(BlockModeError::NotInitialised)
    ));
}
