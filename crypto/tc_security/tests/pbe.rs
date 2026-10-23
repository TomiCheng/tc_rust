//! PBE 工廠：BC 測試的金鑰與 IV、名稱與 OID、每個方案的加解密。

#![cfg(feature = "pbe")]

use std::error::Error;

use tc_block_cipher::KeyParams;
use tc_block_modes::IvParams;
use tc_security::params::AnyParams;
use tc_security::{AnyError, SecurityError, cipher, mac, pbe};

#[allow(dead_code, reason = "沒開對應的 digest 與 cipher 時沒有測試用到")]
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[allow(dead_code, reason = "沒開對應的 digest 與 cipher 時沒有測試用到")]
fn key_and_iv(params: &AnyParams) -> (Vec<u8>, Vec<u8>) {
    (
        KeyParams::key(params).to_vec(),
        IvParams::iv(params).to_vec(),
    )
}

/// 沿著 source 往下找第一個 `E`。
#[allow(dead_code, reason = "沒開對應的 digest 與 cipher 時沒有測試用到")]
fn source<E: Error + 'static>(error: &AnyError) -> Option<&E> {
    let mut source = error.source();
    while let Some(error) = source {
        if let Some(found) = error.downcast_ref() {
            return Some(found);
        }
        source = error.source();
    }
    None
}

#[test]
fn an_unknown_scheme_is_refused() {
    // RC4 的方案要等 RC4 接上 cipher 工廠
    for name in [
        "PBEWITHSHAAND128BITRC4",
        "PBEWITHSHA1ANDDES-ECB",
        "1.2.840.113549.1.12.1.1",
        "",
    ] {
        assert_eq!(
            pbe::get_by_name(name).map(|entry| entry.name()),
            Err(SecurityError::UnknownPbe),
            "{name}"
        );
    }
}

#[cfg(all(feature = "sha1", feature = "desede"))]
#[test]
fn triple_des_is_found_by_every_bc_alias_and_its_pkcs12_oid() {
    for name in [
        "PBEWithSHAAnd3-KeyTripleDES-CBC",
        "pbewithsha-1and3-keydesede-cbc",
        "PBEWITHSHA1AND3-KEYTRIPLEDES-CBC",
        "1.2.840.113549.1.12.1.3",
    ] {
        assert_eq!(
            pbe::get_by_name(name).map(|entry| entry.name()),
            Ok("PBEWITHSHAAND3-KEYTRIPLEDES-CBC"),
            "{name}"
        );
    }
}

// BC PBETest：PBEWithSHA1AndDES 解得開以 DES 金鑰 30e69252758e5346、IV 7c1c1ab9c454a688 加密的資料。
// 工廠同 BC 的 FixDesParity 設 odd parity，DES 不看 parity，所以解得開
#[cfg(all(feature = "sha1", feature = "des"))]
#[test]
fn pbe_with_sha1_and_des_decrypts_what_bcs_pbe_test_encrypts() {
    let entry = pbe::get_by_name("PBEWithSHA1AndDES").unwrap();
    let params = entry
        .generate_cipher_params("password", &hex("7d60435f02e9e0ae"), 2048)
        .unwrap();
    assert_eq!(
        key_and_iv(&params),
        (hex("31e69252758f5246"), hex("7c1c1ab9c454a688"))
    );

    let input = hex("1234567890abcdefabcdef1234567890fedbca098765");
    let raw = AnyParams::new(hex("30e69252758e5346")).with_iv(hex("7c1c1ab9c454a688"));
    let mut des = cipher::get_by_name("DES/CBC/PKCS7PADDING")
        .unwrap()
        .cipher();
    let sealed = cipher::encrypt(&mut des, &raw, &input).unwrap();
    assert_eq!(
        cipher::decrypt(&mut entry.cipher().unwrap(), &params, &sealed).unwrap(),
        input
    );
}

// BC Pkcs12Test 的 Run1 與 Run2："smeg"、一次迭代的 DESede 金鑰（另設 odd parity）與 IV
#[cfg(all(feature = "sha1", feature = "desede"))]
#[test]
fn pkcs12_triple_des_gives_the_key_and_iv_of_bcs_pkcs12_test() {
    let params = pbe::get_by_name("PBEWITHSHAAND3-KEYTRIPLEDES-CBC")
        .unwrap()
        .generate_cipher_params("smeg", &hex("0A58CF64530D823F"), 1)
        .unwrap();
    assert_eq!(
        key_and_iv(&params),
        (
            hex("8aabe6297a6db04643ab5b077951294fb6138f1a2a7fbca2"),
            hex("79993DFE048D3B76")
        )
    );
}

// 期望值由 OpenSSL 3.5 的 `openssl enc -aes-128-cbc -md md5 -P` 印出
#[cfg(all(feature = "md5", feature = "aes"))]
#[test]
fn the_openssl_scheme_gives_the_key_and_iv_of_openssl_enc() {
    let params = pbe::get_by_name("PBEWITHMD5AND128BITAES-CBC-OPENSSL")
        .unwrap()
        .generate_cipher_params(
            "PBEWITHMD5AND128BITAES-CBC-OPENSSL",
            &hex("0001020304050607"),
            1,
        )
        .unwrap();
    assert_eq!(
        key_and_iv(&params),
        (
            hex("65801049C51D116008B04C2972AE409F"),
            hex("B2FF3D10E2ED629D23EF7081C39FBDE6")
        )
    );
}

#[test]
fn every_scheme_works_with_its_cipher_or_mac_and_names_and_oids_are_unique() {
    let mut names = std::collections::HashSet::new();
    let mut oids = std::collections::HashSet::new();
    let message = b"attack at dawn, bring the battery staple";
    for entry in pbe::algorithms() {
        assert!(names.insert(entry.name()), "{entry}");
        for oid in entry.oids() {
            assert!(oids.insert(oid.dotted()), "{entry}");
        }
        let params = entry
            .generate_cipher_params("correct horse", b"saltsalt", 100)
            .unwrap();
        match (entry.cipher(), entry.mac()) {
            (Some(mut scheme_cipher), None) => {
                let sealed = cipher::encrypt(&mut scheme_cipher, &params, message).unwrap();
                assert_eq!(
                    cipher::decrypt(&mut scheme_cipher, &params, &sealed).unwrap(),
                    message,
                    "{entry}"
                );
            }
            (None, Some(mut scheme_mac)) => {
                let tag = mac::calculate(&mut scheme_mac, &params, message).unwrap();
                assert_eq!(KeyParams::key(&params).len(), tag.len(), "{entry}");
            }
            _ => panic!("{entry} has exactly one of a cipher and a MAC"),
        }
    }
}

// BC Pkcs12Test 的 Run3："smeg"、一次迭代的 160 bits MAC 金鑰，也就是 PBEWithHmacSHA1 的金鑰
#[cfg(feature = "sha1")]
#[test]
fn pbe_with_hmac_sha1_gives_the_mac_key_of_bcs_pkcs12_test() {
    let entry = pbe::get_by_name("1.3.14.3.2.26").unwrap();
    assert_eq!(entry.name(), "PBEWITHHMACSHA1");
    assert!(entry.cipher().is_none());
    let params = entry
        .generate_cipher_params("smeg", &hex("3D83C0E4546AC140"), 1)
        .unwrap();
    assert_eq!(
        KeyParams::key(&params),
        hex("8D967D88F6CAA9D714800AB3D48051D63F73A312")
    );
}

#[cfg(all(feature = "md5", feature = "des"))]
#[test]
fn a_zero_iteration_count_is_refused_except_by_openssl() {
    let Err(error) = pbe::get_by_name("PBEWITHMD5ANDDES-CBC")
        .unwrap()
        .generate_cipher_params("password", b"saltsalt", 0)
    else {
        panic!("a count of 0 is refused");
    };
    assert_eq!(
        source::<tc_pbe::PbeError>(&error),
        Some(&tc_pbe::PbeError::InvalidIterationCount(0))
    );
}
