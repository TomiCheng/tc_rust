//! Known-answer tests for RFC 5649 AES Key Wrap with Padding.
//!
//! The AES vectors are the two official examples from RFC 5649 §6 (a 20-octet
//! key → multi-block path, and a 7-octet key → single-block path). The ARIA
//! vectors were produced by an independent OpenSSL-based RFC 5649 implementation
//! that reproduces those official AES vectors, so a match here is agreement
//! between two independent implementations. Construction uses `default()`, which
//! also exercises the aliases' `Default` impl.

use tc_block_cipher::{AesEngine, AesParams, AriaParams};
use tc_cipher_core::{KeyWrap, KeyWrapInit, WrapDirection};
use tc_key_wrap::{AesWrapPadEngine, AriaWrapPadEngine, Rfc5649Error, Rfc5649Params};

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

macro_rules! kat {
    ($name:ident, $engine:ty, $params:ty, $kek:expr, $key:expr, $wrapped:expr) => {
        #[test]
        fn $name() {
            let kek = hex($kek);
            let key = hex($key);
            let wrapped = hex($wrapped);

            let mut w = <$engine>::default();
            w.init(
                WrapDirection::Wrap,
                &Rfc5649Params::new(<$params>::new(&kek).unwrap()),
            )
            .unwrap();
            let mut output = vec![0_u8; w.wrapped_len(key.len()).unwrap()];
            let written = w.wrap_into(&key, &mut output).unwrap();
            assert_eq!(written, output.len());
            assert_eq!(output, wrapped, "wrap 輸出與向量不符");

            w.init(
                WrapDirection::Unwrap,
                &Rfc5649Params::new(<$params>::new(&kek).unwrap()),
            )
            .unwrap();
            let mut recovered = vec![0_u8; w.max_unwrapped_len(wrapped.len()).unwrap()];
            let written = w.unwrap_into(&wrapped, &mut recovered).unwrap();
            assert_eq!(&recovered[..written], key, "unwrap 未還原原始金鑰");
        }
    };
}

// ---- AES：RFC 5649 §6 官方向量 ----
const AES_KEK: &str = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8";

kat!(
    aes_rfc5649_s61_20_octets,
    AesWrapPadEngine,
    AesParams,
    AES_KEK,
    "c37b7e6492584340bed12207808941155068f738",
    "138BDEAA9B8FA7FC61F97742E72248EE5AE6AE5360D1AE6A5F54F373FA543B6A"
);
kat!(
    aes_rfc5649_s62_7_octets,
    AesWrapPadEngine,
    AesParams,
    AES_KEK,
    "466f7250617369",
    "AFBEB0F07DFBF5419200F2CCB50BB24F"
);

// ---- ARIA：與獨立 OpenSSL 實作交叉驗證（128-bit KEK） ----
const ARIA_KEK: &str = "000102030405060708090A0B0C0D0E0F";

kat!(
    aria_wrap_pad_7_octets,
    AriaWrapPadEngine,
    AriaParams,
    ARIA_KEK,
    "466f7250617369",
    "FF5DF3FABA86BD7802800F420B6BB16A"
);
kat!(
    aria_wrap_pad_16_octets,
    AriaWrapPadEngine,
    AriaParams,
    ARIA_KEK,
    "00112233445566778899AABBCCDDEEFF",
    "AC0E22699A036CED63ADEB75F4946F82DC98AD8AF43B24D5"
);
kat!(
    aria_wrap_pad_20_octets,
    AriaWrapPadEngine,
    AriaParams,
    ARIA_KEK,
    "c37b7e6492584340bed12207808941155068f738",
    "9EC1DA50BA6665264E0C75C4C4FD2E652DEB5F4C0F3FCFD478624C1A9AF35FFA"
);
kat!(
    aria_wrap_pad_24_octets,
    AriaWrapPadEngine,
    AriaParams,
    ARIA_KEK,
    "00112233445566778899AABBCCDDEEFF0001020304050607",
    "A08391E5159F4DE68EBD1F9E7DB722E1A9D9AAF206F7DACB62CA0FEAD47C1B96"
);
kat!(
    aria_wrap_pad_32_octets,
    AriaWrapPadEngine,
    AriaParams,
    ARIA_KEK,
    "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
    "1F59D0D10409835594531BF7B721CBF260816766D71BF2647D8BA6AB3125334E34FA018ABB39C280"
);

#[test]
fn tampered_blob_fails_integrity_check() {
    let kek = hex(AES_KEK);
    let mut wrapped = hex("AFBEB0F07DFBF5419200F2CCB50BB24F");
    wrapped[0] ^= 0x01; // 竄改一個 byte

    let mut w = AesWrapPadEngine::default();
    w.init(
        WrapDirection::Unwrap,
        &Rfc5649Params::new(AesParams::new(&kek).unwrap()),
    )
    .unwrap();
    let mut output = vec![0xa5_u8; w.max_unwrapped_len(wrapped.len()).unwrap()];
    assert!(matches!(
        w.unwrap_into(&wrapped, &mut output),
        Err(Rfc5649Error::IntegrityCheckFailed)
    ));
    assert!(
        output.iter().all(|byte| *byte == 0),
        "完整性失敗不得留下未驗證的 key material"
    );
}

#[test]
fn sizing_and_short_output_errors_are_reported_before_processing() {
    let kek = hex(AES_KEK);
    let key = hex("466f7250617369");
    let mut w = AesWrapPadEngine::default();

    assert!(matches!(
        w.wrapped_len(0),
        Err(Rfc5649Error::WrapDataLength)
    ));
    assert_eq!(w.wrapped_len(1).unwrap(), 16);
    assert_eq!(w.wrapped_len(8).unwrap(), 16);
    assert_eq!(w.wrapped_len(9).unwrap(), 24);
    assert_eq!(w.max_unwrapped_len(16).unwrap(), 8);
    assert!(matches!(
        w.max_unwrapped_len(15),
        Err(Rfc5649Error::UnwrapDataLength)
    ));

    w.init(
        WrapDirection::Wrap,
        &Rfc5649Params::new(AesParams::new(&kek).unwrap()),
    )
    .unwrap();
    let mut short = [0_u8; 15];
    assert!(matches!(
        w.wrap_into(&key, &mut short),
        Err(Rfc5649Error::OutputBufferTooShort {
            required: 16,
            available: 15,
        })
    ));
}

#[test]
fn initialized_engine_supports_dynamic_dispatch() {
    let kek = hex(AES_KEK);
    let key = hex("466f7250617369");
    let mut engine = AesWrapPadEngine::default();
    engine
        .init(
            WrapDirection::Wrap,
            &Rfc5649Params::new(AesParams::new(&kek).unwrap()),
        )
        .unwrap();

    let wrapper: &mut dyn KeyWrap<Error = Rfc5649Error<AesEngine>> = &mut engine;
    let mut output = [0_u8; 16];

    assert_eq!(wrapper.wrapped_len(key.len()).unwrap(), output.len());
    assert_eq!(wrapper.wrap_into(&key, &mut output).unwrap(), output.len());
}
