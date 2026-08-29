//! Tests for the DSTU 7624 (Kalyna) counter mode, KCTR.
//!
//! The vectors are from Bouncy Castle's `DSTU7624Test`, which runs the same two
//! vectors through both a block-cipher and a stream-cipher harness (its tests 24
//! and 25 against 26 and 27). This port does the same: the block-aligned vector
//! is checked through `BlockCipher` and `StreamCipher` alike, and the unaligned
//! one — 41 bytes, so not a whole number of blocks — through `StreamCipher`,
//! which is the interface that can express it.
//!
//! Both traits declare `algorithm_name` and `init`, so calls here are qualified
//! with the trait they belong to.

use tc_block_cipher::{Dstu7624Engine, Dstu7624Params};
use tc_block_modes::{CipherModeError, KCtrBlockCipher, KCtrParams};
use tc_cipher_core::{
    BlockCipher, BlockCipherInit, CipherDirection, StreamCipher, StreamCipherInit,
};

/// Parses a hex string into bytes.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const KEY: &str = "000102030405060708090A0B0C0D0E0F";
const IV: &str = "101112131415161718191A1B1C1D1E1F";

/// bc test 24 / 26: 41 bytes, so not a whole number of blocks.
const UNALIGNED_IN: &str =
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748";
const UNALIGNED_OUT: &str =
    "A90A6B9780ABDFDFF64D14F5439E88F266DC50EDD341528DD5E698E2F000CE21F872DAF9FE1811844A";

/// bc test 25 / 27: exactly two 128-bit blocks.
const ALIGNED_IN: &str = "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F";
const ALIGNED_OUT: &str = "B91A7B8790BBCFCFE65D04E5538E98E216AC209DA33122FDA596E8928070BE51";

/// Builds a KCTR mode over DSTU 7624 with a 128-bit block, initialised through
/// the stream-cipher interface.
fn new_stream_mode() -> KCtrBlockCipher<Dstu7624Engine> {
    let mut mode = KCtrBlockCipher::new(Dstu7624Engine::new(128).unwrap());
    let key = hex(KEY);
    let iv = hex(IV);
    StreamCipherInit::init(
        &mut mode,
        &KCtrParams::new(Dstu7624Params::new(&key).unwrap(), &iv),
    )
    .unwrap();
    mode
}

#[test]
fn bc_vector_unaligned_through_stream_interface() {
    let mut mode = new_stream_mode();
    let input = hex(UNALIGNED_IN);
    let mut out = vec![0u8; input.len()];
    let n = mode.process_bytes(&input, &mut out).unwrap();

    assert_eq!(n, input.len());
    assert_eq!(out, hex(UNALIGNED_OUT));
}

#[test]
fn bc_vector_aligned_through_stream_interface() {
    let mut mode = new_stream_mode();
    let input = hex(ALIGNED_IN);
    let mut out = vec![0u8; input.len()];
    mode.process_bytes(&input, &mut out).unwrap();

    assert_eq!(out, hex(ALIGNED_OUT));
}

#[test]
fn bc_vector_aligned_through_block_interface() {
    // 同一組向量走 BlockCipher 介面必須得到相同結果（bc 也是這樣兩邊各測一次）。
    let mut mode = KCtrBlockCipher::new(Dstu7624Engine::new(128).unwrap());
    let key = hex(KEY);
    let iv = hex(IV);
    BlockCipherInit::init(
        &mut mode,
        CipherDirection::Encrypt,
        &KCtrParams::new(Dstu7624Params::new(&key).unwrap(), &iv),
    )
    .unwrap();

    let input = hex(ALIGNED_IN);
    let bs = BlockCipher::block_size(&mode);
    let mut out = vec![0u8; input.len()];
    for (chunk_in, chunk_out) in input.chunks(bs).zip(out.chunks_mut(bs)) {
        let n = mode.process_block(chunk_in, chunk_out).unwrap();
        assert_eq!(n, bs);
    }
    assert_eq!(out, hex(ALIGNED_OUT));
}

#[test]
fn return_byte_matches_process_bytes() {
    let input = hex(ALIGNED_IN);

    let mut bulk = new_stream_mode();
    let mut bulk_out = vec![0u8; input.len()];
    bulk.process_bytes(&input, &mut bulk_out).unwrap();

    let mut single = new_stream_mode();
    let single_out: Vec<u8> = input
        .iter()
        .map(|&b| single.return_byte(b).unwrap())
        .collect();

    assert_eq!(bulk_out, single_out);
}

#[test]
fn reset_restarts_the_keystream() {
    let input = hex(ALIGNED_IN);
    let mut mode = new_stream_mode();

    let mut first = vec![0u8; input.len()];
    mode.process_bytes(&input, &mut first).unwrap();

    mode.reset();
    let mut second = vec![0u8; input.len()];
    mode.process_bytes(&input, &mut second).unwrap();

    assert_eq!(first, second);
    assert_eq!(first, hex(ALIGNED_OUT));
}

#[test]
fn round_trips_and_ignores_the_direction() {
    let plaintext = hex(ALIGNED_IN);

    let mut enc = new_stream_mode();
    let mut ct = vec![0u8; plaintext.len()];
    enc.process_bytes(&plaintext, &mut ct).unwrap();

    // keystream 只由 key 與 IV 決定，故對密文再跑一次即還原。
    let mut dec = KCtrBlockCipher::new(Dstu7624Engine::new(128).unwrap());
    let key = hex(KEY);
    let iv = hex(IV);
    BlockCipherInit::init(
        &mut dec,
        CipherDirection::Decrypt,
        &KCtrParams::new(Dstu7624Params::new(&key).unwrap(), &iv),
    )
    .unwrap();
    let mut back = vec![0u8; ct.len()];
    dec.process_bytes(&ct, &mut back).unwrap();

    assert_eq!(back, plaintext);
}

#[test]
fn reports_its_composed_name_and_errors_before_init() {
    let mut mode = KCtrBlockCipher::new(Dstu7624Engine::new(128).unwrap());
    assert_eq!(StreamCipher::algorithm_name(&mode), "DSTU7624/KCTR");
    assert_eq!(BlockCipher::block_size(&mode), 16);

    let mut out = [0u8; 16];
    assert!(matches!(
        mode.process_bytes(&[0u8; 16], &mut out),
        Err(CipherModeError::NotInitialised)
    ));
    assert!(matches!(
        mode.return_byte(0),
        Err(CipherModeError::NotInitialised)
    ));
}
