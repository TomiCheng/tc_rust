//! Known-answer tests for RFC 3394 AES Key Wrap (NIST / RFC 3394 §4 vectors).
//!
//! §4.1–4.3 use a single data block (n == 1) and §4.4–4.6 use multiple blocks
//! (n > 1), so together they cover both paths of `Rfc3394WrapEngine`. Each vector
//! checks the wrap output and the unwrap round-trip.

use tc_block_cipher::{AesEngine, AesParams};
use tc_cipher_core::{KeyWrap, KeyWrapInit, WrapDirection};
use tc_key_wrap::{Rfc3394Error, Rfc3394Params, Rfc3394WrapEngine};

/// Parses a hex string (ignoring whitespace) into bytes.
fn hex(s: &str) -> Vec<u8> {
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    bytes
        .chunks(2)
        .map(|c| {
            let hi = (c[0] as char).to_digit(16).unwrap();
            let lo = (c[1] as char).to_digit(16).unwrap();
            (hi * 16 + lo) as u8
        })
        .collect()
}

/// Builds an AES `Rfc3394WrapEngine` (AesParams is not Clone, so rebuild it per use).
fn new_engine() -> Rfc3394WrapEngine<AesEngine> {
    Rfc3394WrapEngine::new(AesEngine::new())
}

/// Checks one vector: wrap(key) == wrapped, and unwrap(wrapped) == key.
fn check(kek_hex: &str, key_hex: &str, wrapped_hex: &str) {
    let kek = hex(kek_hex);
    let key = hex(key_hex);
    let wrapped = hex(wrapped_hex);

    let mut engine = new_engine();

    engine
        .init(
            WrapDirection::Wrap,
            &Rfc3394Params::new(AesParams::new(&kek).unwrap()),
        )
        .unwrap();
    let mut out = vec![0_u8; engine.wrapped_len(key.len()).unwrap()];
    let written = engine.wrap_into(&key, &mut out).unwrap();
    assert_eq!(written, out.len());
    assert_eq!(out, wrapped, "wrap 輸出與向量不符");

    engine
        .init(
            WrapDirection::Unwrap,
            &Rfc3394Params::new(AesParams::new(&kek).unwrap()),
        )
        .unwrap();
    let mut back = vec![0_u8; engine.max_unwrapped_len(wrapped.len()).unwrap()];
    let written = engine.unwrap_into(&wrapped, &mut back).unwrap();
    back.truncate(written);
    assert_eq!(back, key, "unwrap 未還原原始金鑰");
}

#[test]
fn rfc3394_s41_128bit_kek_128bit_key() {
    check(
        "000102030405060708090A0B0C0D0E0F",
        "00112233445566778899AABBCCDDEEFF",
        "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
    );
}

#[test]
fn rfc3394_s42_192bit_kek_128bit_key() {
    check(
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "00112233445566778899AABBCCDDEEFF",
        "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
    );
}

#[test]
fn rfc3394_s43_256bit_kek_128bit_key() {
    check(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF",
        "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
    );
}

#[test]
fn rfc3394_s44_192bit_kek_192bit_key() {
    check(
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "00112233445566778899AABBCCDDEEFF0001020304050607",
        "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
    );
}

#[test]
fn rfc3394_s45_256bit_kek_192bit_key() {
    check(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF0001020304050607",
        "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
    );
}

#[test]
fn rfc3394_s46_256bit_kek_256bit_key() {
    check(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
    );
}

#[test]
fn tampered_blob_fails_integrity_check() {
    let kek = hex("000102030405060708090A0B0C0D0E0F");
    let mut wrapped = hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
    wrapped[0] ^= 0x01; // 竄改一個 byte

    let mut engine = new_engine();
    engine
        .init(
            WrapDirection::Unwrap,
            &Rfc3394Params::new(AesParams::new(&kek).unwrap()),
        )
        .unwrap();
    let mut output = vec![0xa5_u8; engine.max_unwrapped_len(wrapped.len()).unwrap()];
    assert!(matches!(
        engine.unwrap_into(&wrapped, &mut output),
        Err(Rfc3394Error::IntegrityCheckFailed)
    ));
    assert!(
        output.iter().all(|byte| *byte == 0),
        "完整性失敗不得留下未驗證的 key material"
    );
}

#[test]
fn custom_iv_round_trips() {
    let kek = hex("000102030405060708090A0B0C0D0E0F");
    let key = hex("00112233445566778899AABBCCDDEEFF");
    let iv = [0x01u8; 8];

    let mut engine = new_engine();
    engine
        .init(
            WrapDirection::Wrap,
            &Rfc3394Params::with_iv(AesParams::new(&kek).unwrap(), iv),
        )
        .unwrap();
    let mut wrapped = vec![0_u8; engine.wrapped_len(key.len()).unwrap()];
    engine.wrap_into(&key, &mut wrapped).unwrap();

    engine
        .init(
            WrapDirection::Unwrap,
            &Rfc3394Params::with_iv(AesParams::new(&kek).unwrap(), iv),
        )
        .unwrap();
    let mut recovered = vec![0_u8; engine.max_unwrapped_len(wrapped.len()).unwrap()];
    let written = engine.unwrap_into(&wrapped, &mut recovered).unwrap();
    assert_eq!(&recovered[..written], key);
}

#[test]
fn sizing_and_short_output_errors_are_reported_before_processing() {
    let kek = hex("000102030405060708090A0B0C0D0E0F");
    let key = hex("00112233445566778899AABBCCDDEEFF");
    let mut engine = new_engine();

    assert!(matches!(
        engine.wrapped_len(7),
        Err(Rfc3394Error::WrapDataLength)
    ));
    assert!(matches!(
        engine.max_unwrapped_len(8),
        Err(Rfc3394Error::UnwrapDataLength)
    ));
    assert_eq!(engine.wrapped_len(key.len()).unwrap(), 24);
    assert_eq!(engine.max_unwrapped_len(24).unwrap(), 16);

    engine
        .init(
            WrapDirection::Wrap,
            &Rfc3394Params::new(AesParams::new(&kek).unwrap()),
        )
        .unwrap();
    let mut short = [0_u8; 23];
    assert!(matches!(
        engine.wrap_into(&key, &mut short),
        Err(Rfc3394Error::OutputBufferTooShort {
            required: 24,
            available: 23,
        })
    ));
}

#[test]
fn initialized_engine_supports_dynamic_dispatch() {
    let kek = hex("000102030405060708090A0B0C0D0E0F");
    let key = hex("00112233445566778899AABBCCDDEEFF");
    let mut engine = new_engine();
    engine
        .init(
            WrapDirection::Wrap,
            &Rfc3394Params::new(AesParams::new(&kek).unwrap()),
        )
        .unwrap();

    let wrapper: &mut dyn KeyWrap<Error = Rfc3394Error<AesEngine>> = &mut engine;
    let mut output = [0_u8; 24];

    assert_eq!(wrapper.wrapped_len(key.len()).unwrap(), output.len());
    assert_eq!(wrapper.wrap_into(&key, &mut output).unwrap(), output.len());
}
