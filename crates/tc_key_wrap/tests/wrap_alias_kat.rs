//! Known-answer tests for the RFC 3394 wrap aliases over ARIA, Camellia, and SEED.
//!
//! No official spec publishes key-wrap vectors for these ciphers (RFC 3657 for
//! Camellia and RFC 4010 for SEED only reference RFC 3394's mechanism). These
//! vectors were therefore produced by an independent RFC 3394 implementation
//! built on OpenSSL's ECB primitive, which was first validated against the AES
//! NIST vectors of RFC 3394 §4 — so a match here is agreement between two
//! independent implementations. Each vector checks both wrap and the unwrap
//! round-trip; construction uses `default()`, which also exercises the aliases'
//! `Default` impl.

use tc_block_cipher::{AriaParams, CamelliaParams, SeedParams};
use tc_cipher_core::{KeyWrap, KeyWrapInit, WrapDirection};
use tc_key_wrap::{AriaWrapEngine, CamelliaWrapEngine, Rfc3394Params, SeedWrapEngine};

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

// 共用的 KEK 與 key data（與 RFC 3394 §4 相同的位元組樣式，便於對照）。
const K128: &str = "000102030405060708090A0B0C0D0E0F";
const K192: &str = "000102030405060708090A0B0C0D0E0F1011121314151617";
const K256: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
const D128: &str = "00112233445566778899AABBCCDDEEFF";
const D192: &str = "00112233445566778899AABBCCDDEEFF0001020304050607";
const D256: &str = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";

macro_rules! kat {
    ($name:ident, $engine:ty, $params:ty, $kek:expr, $key:expr, $wrapped:expr) => {
        #[test]
        fn $name() {
            let kek = hex($kek);
            let key = hex($key);
            let wrapped = hex($wrapped);

            let mut w = <$engine>::default();
            let params = Rfc3394Params::new(<$params>::new(&kek).unwrap());
            KeyWrapInit::init(&mut w, WrapDirection::Wrap, &params).unwrap();
            let mut actual = vec![0_u8; w.wrapped_len(key.len()).unwrap()];
            let written = w.wrap_into(&key, &mut actual).unwrap();
            assert_eq!(written, actual.len());
            assert_eq!(actual, wrapped, "wrap 輸出與參考向量不符");

            KeyWrapInit::init(&mut w, WrapDirection::Unwrap, &params).unwrap();
            let mut recovered = vec![0_u8; w.max_unwrapped_len(wrapped.len()).unwrap()];
            let recovered_len = w.unwrap_into(&wrapped, &mut recovered).unwrap();
            assert_eq!(&recovered[..recovered_len], key, "unwrap 未還原原始金鑰");
        }
    };
}

// ---- Camellia ----
kat!(camellia_k128_d128, CamelliaWrapEngine, CamelliaParams, K128, D128,
    "635D6AC46EEDEBD3A7F4A06421A4CBD1746B24795BA2F708");
kat!(camellia_k192_d128, CamelliaWrapEngine, CamelliaParams, K192, D128,
    "FE8F5C4E2164CDFE36233C9F898F93DF6E6F1D892D187742");
kat!(camellia_k256_d128, CamelliaWrapEngine, CamelliaParams, K256, D128,
    "B43E6793EE3B35B7698253B26BAD0CA2D5E7793C6F5DDD48");
kat!(camellia_k192_d192, CamelliaWrapEngine, CamelliaParams, K192, D192,
    "EA7B7515BDE2F268849FA2B4D96ADBACC8111073D463DA9FB5E7648F6DD2FE76");
kat!(camellia_k256_d192, CamelliaWrapEngine, CamelliaParams, K256, D192,
    "C7CB865E14A7DC00B339F9D9041ED4C3BA4E34EEDADD7A1C5F98534180CD59BE");
kat!(camellia_k256_d256, CamelliaWrapEngine, CamelliaParams, K256, D256,
    "96A502A1E0C12700EC01D9E9B3688D50B7AE25FBAE06DD18F0E30092AC1ABD5BC7575DA930DF1636");

// ---- ARIA ----
kat!(aria_k128_d128, AriaWrapEngine, AriaParams, K128, D128,
    "A93F148D4909D85F1AAE656909879275AE597B3ACF9D60DB");
kat!(aria_k192_d128, AriaWrapEngine, AriaParams, K192, D128,
    "62C0CC597CEA0A97C1DDFD9384BA51A9F4EC7AAC30F7CEDC");
kat!(aria_k256_d128, AriaWrapEngine, AriaParams, K256, D128,
    "1F68AC246E2519B0235E1474867B08F606BCF85BEF006EBA");
kat!(aria_k192_d192, AriaWrapEngine, AriaParams, K192, D192,
    "D3DE092CDAE2C71E85AA964924DCE3C96736BD22CAD51F75823102BBB305D230");
kat!(aria_k256_d192, AriaWrapEngine, AriaParams, K256, D192,
    "32E13D029906B74EAD0BD0CF2F4F73DFAD439B0D27AB591E6CFEFDD7DB5A2A98");
kat!(aria_k256_d256, AriaWrapEngine, AriaParams, K256, D256,
    "9E98AAD469E60840C258F8396AA05F826F7353BDD1257F909C5576967B0F8C7BCD9FE4157BF4D844");

// ---- SEED（僅 128-bit KEK）----
kat!(seed_k128_d128, SeedWrapEngine, SeedParams, K128, D128,
    "BF71F77138B5AFEA05232A8DAD54024E812DC8DD7D132559");
kat!(seed_k128_d192, SeedWrapEngine, SeedParams, K128, D192,
    "405BBC1A0F41638D8FAC416726D69F4D64742DA5A8702B34858A395EDA259AEF");
kat!(seed_k128_d256, SeedWrapEngine, SeedParams, K128, D256,
    "18C0C31B0C1ED128C6A3098047ACA859C9D3E743B8644E22759EB7D804D8B0D4DAF098C267120083");
