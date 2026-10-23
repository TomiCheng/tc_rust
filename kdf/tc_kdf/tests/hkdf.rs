#![cfg(feature = "hkdf")]

use tc_digest::Digest;
use tc_kdf::{Hkdf, HkdfParamsRef, Kdf, KdfError, KdfInit};
use tc_sha::{Sha1Digest, Sha256Digest};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn okm<D: Digest>(digest: D, params: HkdfParamsRef<'_>, len: usize) -> Vec<u8> {
    let mut hkdf = Hkdf::new(digest);
    hkdf.init(&params).unwrap();
    let mut output = vec![0; len];
    assert_eq!(hkdf.generate_bytes(&mut output), Ok(len));
    output
}

const LONG_IKM: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f";
const LONG_SALT: &str = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
const LONG_INFO: &str = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

#[test]
fn hkdf_sha256_matches_rfc_5869_test_cases_1_to_3() {
    let (ikm, salt, info) = (
        hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        hex("000102030405060708090a0b0c"),
        hex("f0f1f2f3f4f5f6f7f8f9"),
    );
    assert_eq!(
        okm(
            Sha256Digest::new(),
            HkdfParamsRef::new(&ikm, &salt, &info),
            42
        ),
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );

    let (long_ikm, long_salt, long_info) = (hex(LONG_IKM), hex(LONG_SALT), hex(LONG_INFO));
    assert_eq!(
        okm(
            Sha256Digest::new(),
            HkdfParamsRef::new(&long_ikm, &long_salt, &long_info),
            82
        ),
        hex(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        )
    );

    assert_eq!(
        okm(Sha256Digest::new(), HkdfParamsRef::new(&ikm, &[], &[]), 42),
        hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    );
}

#[test]
fn hkdf_sha1_matches_rfc_5869_test_cases_4_to_7() {
    let (salt, info) = (
        hex("000102030405060708090a0b0c"),
        hex("f0f1f2f3f4f5f6f7f8f9"),
    );
    assert_eq!(
        okm(
            Sha1Digest::new(),
            HkdfParamsRef::new(&hex("0b0b0b0b0b0b0b0b0b0b0b"), &salt, &info),
            42
        ),
        hex("085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896")
    );

    let (long_ikm, long_salt, long_info) = (hex(LONG_IKM), hex(LONG_SALT), hex(LONG_INFO));
    assert_eq!(
        okm(
            Sha1Digest::new(),
            HkdfParamsRef::new(&long_ikm, &long_salt, &long_info),
            82
        ),
        hex(
            "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4"
        )
    );

    for (ikm, expected) in [
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
        ),
        (
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
        ),
    ] {
        assert_eq!(
            okm(
                Sha1Digest::new(),
                HkdfParamsRef::new(&hex(ikm), &[], &[]),
                42
            ),
            hex(expected),
            "{ikm}"
        );
    }
}

#[test]
fn expand_only_with_test_case_7s_prk_gives_its_okm() {
    // BC 的 A.101：拿 test case 7 的 PRK 直接展開
    let prk = hex("2adccada18779e7c2077ad2eb19d3f3e731385dd");
    assert_eq!(
        okm(Sha1Digest::new(), HkdfParamsRef::expand_only(&prk, &[]), 42),
        hex("2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48")
    );
}

#[test]
fn split_calls_continue_the_same_output() {
    let (ikm, salt, info) = (hex(LONG_IKM), hex(LONG_SALT), hex(LONG_INFO));
    let params = HkdfParamsRef::new(&ikm, &salt, &info);
    let whole = okm(Sha256Digest::new(), params, 82);

    let mut hkdf = Hkdf::new(Sha256Digest::new());
    hkdf.init(&params).unwrap();
    let mut pieces = Vec::new();
    for len in [1, 30, 2, 33, 16] {
        let mut piece = vec![0; len];
        hkdf.generate_bytes(&mut piece).unwrap();
        pieces.extend(piece);
    }
    assert_eq!(pieces, whole);
}

#[test]
fn output_stops_at_255_blocks_until_the_next_init() {
    let prk = hex("2adccada18779e7c2077ad2eb19d3f3e731385dd");
    let params = HkdfParamsRef::expand_only(&prk, &[]);
    let mut hkdf = Hkdf::new(Sha1Digest::new());
    hkdf.init(&params).unwrap();
    let mut all = vec![0; 255 * 20 - 1];
    hkdf.generate_bytes(&mut all).unwrap();
    assert!(all[..20].iter().any(|&byte| byte != 0));
    assert_eq!(
        hkdf.generate_bytes(&mut [0; 2]),
        Err(KdfError::OutputTooLong)
    );
    assert_eq!(hkdf.generate_bytes(&mut [0; 1]), Ok(1));
    assert_eq!(
        hkdf.generate_bytes(&mut [0; 1]),
        Err(KdfError::OutputTooLong)
    );

    hkdf.init(&params).unwrap();
    assert_eq!(hkdf.generate_bytes(&mut [0; 20]), Ok(20));
}

#[test]
fn generating_before_init_fails() {
    let mut hkdf = Hkdf::new(Sha256Digest::new());
    assert_eq!(
        hkdf.generate_bytes(&mut [0; 16]),
        Err(KdfError::NotInitialised)
    );
}
