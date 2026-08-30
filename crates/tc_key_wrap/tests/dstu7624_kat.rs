//! Known-answer tests for the DSTU 7624 (Kalyna) key wrap.
//!
//! Vectors are from Bouncy Castle's `DSTU7624Test` key-wrap cases, covering the
//! 128-, 256-, and 512-bit block sizes with keys of the block size and twice the
//! block size. Each vector checks the wrap output and the unwrap round-trip.

use tc_block_cipher::Dstu7624Params;
use tc_block_cipher::dstu7624::{Dstu7624Config, ValidDstu7624Config};
use tc_cipher_core::{KeyWrap, KeyWrapInit, WrapDirection};
use tc_key_wrap::{Dstu7624WrapEngine, Dstu7624WrapError};

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

/// Checks one vector: wrap(input) == wrapped, and unwrap(wrapped) == input.
fn check<const BLOCK_WORDS: usize, const KEY_WORDS: usize>(
    key_hex: &str,
    input_hex: &str,
    wrapped_hex: &str,
) where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    let key = hex(key_hex);
    let input = hex(input_hex);
    let wrapped = hex(wrapped_hex);

    let mut w = Dstu7624WrapEngine::<BLOCK_WORDS, KEY_WORDS>::new();

    w.init(
        WrapDirection::Wrap,
        &Dstu7624Params::<KEY_WORDS>::new(&key).unwrap(),
    )
    .unwrap();
    let mut output = vec![0_u8; w.wrapped_len(input.len()).unwrap()];
    let written = w.wrap_into(&input, &mut output).unwrap();
    assert_eq!(written, output.len());
    assert_eq!(output, wrapped, "wrap 輸出與向量不符");

    w.init(
        WrapDirection::Unwrap,
        &Dstu7624Params::<KEY_WORDS>::new(&key).unwrap(),
    )
    .unwrap();
    let mut recovered = vec![0_u8; w.max_unwrapped_len(wrapped.len()).unwrap()];
    let written = w.unwrap_into(&wrapped, &mut recovered).unwrap();
    assert_eq!(written, recovered.len());
    assert_eq!(recovered, input, "unwrap 未還原原始資料");
}

#[test]
fn kw_128_block_key() {
    check::<2, 2>(
        "000102030405060708090A0B0C0D0E0F",
        "101112131415161718191A1B1C1D1E1F20219000000000000000800000000000",
        "0EA983D6CE48484D51462C32CC61672210FCC44196ABE635BAF878FDB83E1A63114128585D49DB355C5819FD38039169",
    );
}

#[test]
fn kw_128_double_key() {
    check::<2, 4>(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
        "2D09A7C18E6A5A0816331EC27CEA596903F77EC8D63F3BDB73299DE7FD9F4558E05992B0B24B39E02EA496368E0841CC1E3FA44556A3048C5A6E9E335717D17D",
    );
}

#[test]
fn kw_256_block_key() {
    check::<4, 4>(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
        "BE59D3C3C31B2685A8FA57CD000727F16AF303F0D87BC2D7ABD80DC2796BBC4CDBC4E0408943AF4DAF7DE9084DC81BFEF15FDCDD0DF399983DF69BF730D7AE2A199CA4F878E4723B7171DD4D1E8DF59C0F25FA0C20946BA64F9037D724BB1D50B6C2BD9788B2AF83EF6163087CD2D4488BC19F3A858D813E3A8947A529B6D65D",
    );
}

#[test]
fn kw_256_double_key() {
    check::<4, 8>(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
        "599217EB2B5270ECEF0BB716D70E251234A2451CE04FCFBAEEA92022C581F19B7C9386BB7476B4AD721D40778F49062C3605F1E8FAC9F3F3AC04E46E89E1844DBF4F18FA9303B288741ABD71013CF208F31B4C76FBE342F89B1ABFD97E830457555651B74D3CCDBF94CC5E5EEC22821536A96F44C8BC4346B0271303E67FD313",
    );
}

#[test]
fn kw_512_double_key() {
    check::<8, 8>(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
        "9618AE6065069D5054464040F17337D58BEB51AE92391D740BDF7ABB239709C46270832039FF045BCF7878E7DA9C3B4CF89326CA8B4D29DB8680EEAE1B5A18463284713A323A69AEBF33CFC4B11283C7C8041FFC97668EDF727823411C9559816C108C11EC401643765527860D8DA0ED7254792C21DB775DEB1D6971C924CC83EB626173D894694943B1828ABDE8F9495BCEBA9AC3A4A03592C085AA29CC9A0C65786E631A702D589B819C89E79EEFF29C4EC312C8860BB68F02272EA770FB8D",
    );
}

#[test]
fn tampered_blob_fails_integrity_check() {
    let key = hex("000102030405060708090A0B0C0D0E0F");
    let mut wrapped = hex(
        "0EA983D6CE48484D51462C32CC61672210FCC44196ABE635BAF878FDB83E1A63114128585D49DB355C5819FD38039169",
    );
    wrapped[0] ^= 0x01; // 竄改一個 byte

    let mut w = Dstu7624WrapEngine::<2, 2>::new();
    w.init(
        WrapDirection::Unwrap,
        &Dstu7624Params::<2>::new(&key).unwrap(),
    )
    .unwrap();
    let mut output = vec![0xa5_u8; w.max_unwrapped_len(wrapped.len()).unwrap()];
    assert!(matches!(
        w.unwrap_into(&wrapped, &mut output),
        Err(Dstu7624WrapError::IntegrityCheckFailed)
    ));
    assert!(
        output.iter().all(|byte| *byte == 0),
        "完整性失敗不得留下未驗證的 key material"
    );
}

#[test]
fn sizing_and_short_output_errors_are_reported_before_processing() {
    let key = hex("000102030405060708090A0B0C0D0E0F");
    let input = [0_u8; 16];
    let mut w = Dstu7624WrapEngine::<2, 2>::new();

    assert_eq!(w.wrapped_len(0).unwrap(), 16);
    assert_eq!(w.wrapped_len(16).unwrap(), 32);
    assert!(matches!(
        w.wrapped_len(15),
        Err(Dstu7624WrapError::WrapDataLength)
    ));
    assert_eq!(w.max_unwrapped_len(16).unwrap(), 0);
    assert_eq!(w.max_unwrapped_len(32).unwrap(), 16);
    assert!(matches!(
        w.max_unwrapped_len(15),
        Err(Dstu7624WrapError::UnwrapDataLength)
    ));

    w.init(
        WrapDirection::Wrap,
        &Dstu7624Params::<2>::new(&key).unwrap(),
    )
    .unwrap();
    let mut short = [0_u8; 31];
    assert!(matches!(
        w.wrap_into(&input, &mut short),
        Err(Dstu7624WrapError::OutputBufferTooShort {
            required: 32,
            available: 31,
        })
    ));
}

#[test]
fn empty_input_round_trips() {
    let key = hex("000102030405060708090A0B0C0D0E0F");
    let params = Dstu7624Params::<2>::new(&key).unwrap();
    let mut w = Dstu7624WrapEngine::<2, 2>::new();

    w.init(WrapDirection::Wrap, &params).unwrap();
    let mut wrapped = [0_u8; 16];
    assert_eq!(w.wrap_into(&[], &mut wrapped).unwrap(), wrapped.len());

    w.init(WrapDirection::Unwrap, &params).unwrap();
    assert_eq!(w.unwrap_into(&wrapped, &mut []).unwrap(), 0);
}

#[test]
fn initialized_engine_supports_dynamic_dispatch() {
    let key = hex("000102030405060708090A0B0C0D0E0F");
    let input = [0_u8; 16];
    let mut engine = Dstu7624WrapEngine::<2, 2>::new();
    engine
        .init(
            WrapDirection::Wrap,
            &Dstu7624Params::<2>::new(&key).unwrap(),
        )
        .unwrap();

    let wrapper: &mut dyn KeyWrap<Error = Dstu7624WrapError> = &mut engine;
    let mut output = [0_u8; 32];

    assert_eq!(wrapper.wrapped_len(input.len()).unwrap(), output.len());
    assert_eq!(
        wrapper.wrap_into(&input, &mut output).unwrap(),
        output.len()
    );
}
