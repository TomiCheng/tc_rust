//! Tests for the GOST counter mode (GCTR) and OpenPGP's CFB variant.
//!
//! The GCTR vectors come from Bouncy Castle's `GOST28147Test`, which is the only
//! published source that exercises this mode. No comparable vectors exist for
//! OpenPGP CFB, so that mode is checked by round-tripping across the
//! resynchronisation boundary — the third block onwards runs on a register that
//! has been shifted, so a round trip over four blocks covers every branch.

use tc_block_cipher::{
    AES_BLOCK_BYTES, AesEngine, AesParams, GOST28147_BLOCK_BYTES, Gost28147Engine, Gost28147Params,
    Gost28147SBox,
};
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_cipher_modes::{
    CipherModeError, GofbBlockCipher, GofbParams, OpenPgpCfbBlockCipher, OpenPgpCfbParams,
};

/// Parses a hex string into bytes.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Feeds `input` through `mode` one block at a time.
fn run<M: BlockCipher>(mode: &mut M, input: &[u8]) -> Vec<u8> {
    let bs = mode.block_size();
    let mut out = vec![0u8; input.len()];
    for (chunk_in, chunk_out) in input.chunks(bs).zip(out.chunks_mut(bs)) {
        let n = mode.process_block(chunk_in, chunk_out).unwrap();
        assert_eq!(n, bs);
    }
    out
}

// ---- GCTR ----

/// The custom S-box used by the multi-block bc vectors.
const TEST_S_BOX: [u8; 128] = [
    0xE, 0x3, 0xC, 0xD, 0x1, 0xF, 0xA, 0x9, 0xB, 0x6, 0x2, 0x7, 0x5, 0x0, 0x8, 0x4, //
    0xD, 0x9, 0x0, 0x4, 0x7, 0x1, 0x3, 0xB, 0x6, 0xC, 0x2, 0xA, 0xF, 0xE, 0x5, 0x8, //
    0x8, 0xB, 0xA, 0x7, 0x1, 0xD, 0x5, 0xC, 0x6, 0x3, 0x9, 0x0, 0xF, 0xE, 0x2, 0x4, //
    0xD, 0x7, 0xC, 0x9, 0xF, 0x0, 0x5, 0x8, 0xA, 0x2, 0xB, 0x6, 0x4, 0x3, 0x1, 0xE, //
    0xB, 0x4, 0x6, 0x5, 0x0, 0xF, 0x1, 0xC, 0x9, 0xE, 0xD, 0x8, 0x3, 0x7, 0xA, 0x2, //
    0xD, 0xF, 0x9, 0x4, 0x2, 0xC, 0x5, 0xA, 0x6, 0x0, 0x3, 0x8, 0x7, 0xE, 0x1, 0xB, //
    0xF, 0xE, 0x9, 0x5, 0xB, 0x2, 0x1, 0x8, 0x6, 0x0, 0xD, 0x3, 0x4, 0x7, 0xC, 0xA, //
    0xA, 0x3, 0xE, 0x2, 0x0, 0x1, 0x4, 0x6, 0xB, 0x8, 0xC, 0x7, 0xD, 0x5, 0xF, 0x9,
];

#[test]
fn bc_gost_vector_default_s_box() {
    // bc GOST28147Test 第 3 組；只取第一個完整分組（原向量尾端有 3 個位元組
    // 的部分分組，本 API 只處理完整分組）。
    let key = hex("0011223344556677889900112233445566778899001122334455667788990011");
    let iv = hex("1234567890abcdef");

    let mut mode = GofbBlockCipher::new(Gost28147Engine::new()).unwrap();
    mode.init(
        CipherDirection::Encrypt,
        &GofbParams::with_iv(Gost28147Params::new(&key).unwrap(), &iv),
    )
    .unwrap();

    let ct = run(&mut mode, &hex("bc350e71aa113457"));
    assert_eq!(ct, hex("8824c124c4fd1430"));
}

#[test]
fn bc_gost_vector_custom_s_box_two_blocks() {
    // bc GOST28147Test 第 15 組：兩個完整分組，涵蓋計數器遞增。
    let key = hex("0A43145BA8B9E9FF0AEA67D3F26AD87854CED8D9017B3D33ED81301F90FDF993");
    let iv = hex("8001069080010690");

    let mut mode = GofbBlockCipher::new(Gost28147Engine::new()).unwrap();
    mode.init(
        CipherDirection::Encrypt,
        &GofbParams::with_iv(
            Gost28147Params::with_custom_s_box(&key, &TEST_S_BOX).unwrap(),
            &iv,
        ),
    )
    .unwrap();

    let ct = run(&mut mode, &hex("094C912C5EFDD703D42118971694580B"));
    assert_eq!(ct, hex("2707B58DF039D1A64460735FFE76D55F"));
}

#[test]
fn bc_gost_vector_custom_s_box_second_iv() {
    // bc GOST28147Test 第 16 組。
    let key = hex("0A43145BA8B9E9FF0AEA67D3F26AD87854CED8D9017B3D33ED81301F90FDF993");
    let iv = hex("800107A0800107A0");

    let mut mode = GofbBlockCipher::new(Gost28147Engine::new()).unwrap();
    mode.init(
        CipherDirection::Encrypt,
        &GofbParams::with_iv(
            Gost28147Params::with_custom_s_box(&key, &TEST_S_BOX).unwrap(),
            &iv,
        ),
    )
    .unwrap();

    let ct = run(&mut mode, &hex("FE780800E0690083F20C010CF00C0329"));
    assert_eq!(ct, hex("9AF623DFF948B413B53171E8D546188D"));
}

#[test]
fn gctr_ignores_the_direction_and_round_trips() {
    let key = hex("0011223344556677889900112233445566778899001122334455667788990011");
    let iv = hex("1234567890abcdef");
    let plaintext = hex("bc350e71aa113457bc350e71aa113457");

    let encrypt = |direction, input: &[u8]| {
        let mut mode = GofbBlockCipher::new(Gost28147Engine::new()).unwrap();
        mode.init(
            direction,
            &GofbParams::with_iv(
                Gost28147Params::with_s_box(&key, Gost28147SBox::EncryptionA).unwrap(),
                &iv,
            ),
        )
        .unwrap();
        let mut m = mode;
        run(&mut m, input)
    };

    // keystream 只由 key 與 IV 決定，加解密是同一操作。
    let ct = encrypt(CipherDirection::Encrypt, &plaintext);
    assert_eq!(encrypt(CipherDirection::Decrypt, &plaintext), ct);
    assert_eq!(encrypt(CipherDirection::Decrypt, &ct), plaintext);
}

#[test]
fn gctr_reports_its_name_and_rejects_a_wrong_block_size() {
    let mode = GofbBlockCipher::new(Gost28147Engine::new()).unwrap();
    assert_eq!(mode.algorithm_name(), "Gost28147/GCTR");
    assert_eq!(mode.block_size(), GOST28147_BLOCK_BYTES);

    // GCTR 只定義於 64-bit 分組，AES 的 128-bit 應被拒絕。
    assert!(matches!(
        GofbBlockCipher::new(AesEngine::new()),
        Err(CipherModeError::UnsupportedBlockSize {
            actual: 16,
            required: 8
        })
    ));
}

// ---- OpenPGP CFB ----

fn openpgp(direction: CipherDirection, iv: &[u8], input: &[u8]) -> Vec<u8> {
    let key = hex("000102030405060708090a0b0c0d0e0f");
    let mut mode = OpenPgpCfbBlockCipher::new(AesEngine::new());
    mode.init(
        direction,
        &OpenPgpCfbParams::with_iv(AesParams::new(&key).unwrap(), iv),
    )
    .unwrap();
    run(&mut mode, input)
}

#[test]
fn openpgp_cfb_round_trips_across_the_resync() {
    // 四個分組會走過全部三個分支：第一塊、重新同步的第二塊、之後的穩定狀態。
    let iv = vec![0u8; AES_BLOCK_BYTES];
    let plaintext = hex(concat!(
        "000102030405060708090a0b0c0d0e0f",
        "101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f",
        "303132333435363738393a3b3c3d3e3f",
    ));

    let ct = openpgp(CipherDirection::Encrypt, &iv, &plaintext);
    assert_ne!(ct, plaintext);
    assert_eq!(openpgp(CipherDirection::Decrypt, &iv, &ct), plaintext);
}

#[test]
fn openpgp_cfb_first_block_is_plain_cfb() {
    // 第一塊尚未重新同步，等同於 keystream = E(IV) 的一般 CFB。
    let key = hex("000102030405060708090a0b0c0d0e0f");
    let iv = hex("0f0e0d0c0b0a09080706050403020100");
    let plaintext = hex("00112233445566778899aabbccddeeff");

    let ct = openpgp(CipherDirection::Encrypt, &iv, &plaintext);

    let mut bare = AesEngine::new();
    bare.init(CipherDirection::Encrypt, &AesParams::new(&key).unwrap())
        .unwrap();
    let mut keystream = [0u8; AES_BLOCK_BYTES];
    bare.process_block(&iv, &mut keystream).unwrap();

    let expected: Vec<u8> = keystream
        .iter()
        .zip(plaintext.iter())
        .map(|(k, p)| k ^ p)
        .collect();
    assert_eq!(ct, expected);
}

#[test]
fn openpgp_cfb_resync_makes_the_third_block_differ_from_plain_cfb() {
    // 重新同步後，第三塊起的暫存器已偏移，密文必定與一般 CFB 不同。
    use tc_cipher_modes::{CfbBlockCipher, CfbParams};

    let key = hex("000102030405060708090a0b0c0d0e0f");
    let iv = vec![0u8; AES_BLOCK_BYTES];
    let plaintext = hex(concat!(
        "000102030405060708090a0b0c0d0e0f",
        "101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f",
    ));

    let pgp_ct = openpgp(CipherDirection::Encrypt, &iv, &plaintext);

    let mut plain = CfbBlockCipher::new(AesEngine::new(), 128).unwrap();
    plain
        .init(
            CipherDirection::Encrypt,
            &CfbParams::with_iv(AesParams::new(&key).unwrap(), &iv),
        )
        .unwrap();
    let plain_ct = run(&mut plain, &plaintext);

    // 第一塊相同，第三塊因重新同步而不同。
    assert_eq!(pgp_ct[..AES_BLOCK_BYTES], plain_ct[..AES_BLOCK_BYTES]);
    assert_ne!(pgp_ct[AES_BLOCK_BYTES * 2..], plain_ct[AES_BLOCK_BYTES * 2..]);
}

#[test]
fn openpgp_cfb_reports_its_name_and_errors_before_init() {
    let mut mode = OpenPgpCfbBlockCipher::new(AesEngine::new());
    assert_eq!(mode.algorithm_name(), "AES/OpenPGPCFB");
    assert_eq!(mode.block_size(), AES_BLOCK_BYTES);

    let input = [0u8; AES_BLOCK_BYTES];
    let mut out = [0u8; AES_BLOCK_BYTES];
    assert!(matches!(
        mode.process_block(&input, &mut out),
        Err(CipherModeError::NotInitialised)
    ));
}
