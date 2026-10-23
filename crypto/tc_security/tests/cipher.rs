//! cipher 工廠的 AES：已知答案、名稱與 OID 查詢，以及 `init` 對參數的檢查。

#![cfg(feature = "aes")]

use tc_security::SecurityError;
use tc_security::cipher::{self, Algorithm, Mode, Padding};
use tc_security::params::AnyParams;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn name_of(name: &str) -> Result<String, SecurityError> {
    cipher::get_by_name(name).map(|entry| entry.name().to_string())
}

#[test]
fn aes_matches_the_nist_sp_800_38a_vectors() {
    // F.1.1、F.2.1、F.3.13、F.4.1、F.5.1 的第一個區塊
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let plaintext = hex("6bc1bee22e409f96e93d7e117393172a");
    let iv = "000102030405060708090a0b0c0d0e0f";
    for (name, iv, expected) in [
        ("AES/ECB/NOPADDING", "", "3ad77bb40d7a3660a89ecaf32466ef97"),
        ("AES/CBC/NOPADDING", iv, "7649abac8119b246cee98e9b12e9197d"),
        ("AES/CFB/NOPADDING", iv, "3b3fd92eb72dad20333449f8e83cfb4a"),
        ("AES/OFB/NOPADDING", iv, "3b3fd92eb72dad20333449f8e83cfb4a"),
        (
            "AES/CTR/NOPADDING",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "874d6191b620e3261bef6864990db6ce",
        ),
    ] {
        let entry = cipher::get_by_name(name).unwrap();
        let params = if iv.is_empty() {
            AnyParams::new(key.clone())
        } else {
            AnyParams::new(key.clone()).with_iv(hex(iv))
        };
        assert_eq!(
            cipher::encrypt(&mut entry.cipher(), &params, &plaintext).unwrap(),
            hex(expected),
            "{name}"
        );
    }
}

#[test]
fn aes_gcm_matches_the_gcm_specification_test_cases() {
    let entry = cipher::get_by_name("AES/GCM/NOPADDING").unwrap();

    // 測試案例 2：全零的金鑰、nonce 與明文
    let params = AnyParams::aead(vec![0; 16], 128, vec![0; 12], Vec::new());
    assert_eq!(
        cipher::encrypt(&mut entry.cipher(), &params, &[0; 16]).unwrap(),
        hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
    );

    // 測試案例 3
    let params = AnyParams::aead(
        hex("feffe9928665731c6d6a8f9467308308"),
        128,
        hex("cafebabefacedbaddecaf888"),
        Vec::new(),
    );
    let plaintext = hex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    );
    assert_eq!(
        cipher::encrypt(&mut entry.cipher(), &params, &plaintext).unwrap(),
        hex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
             4d5c2af327cd64a62cf35abd2ba6fab4"
        )
    );

    // 測試案例 4：有 AAD
    let params = AnyParams::aead(
        hex("feffe9928665731c6d6a8f9467308308"),
        128,
        hex("cafebabefacedbaddecaf888"),
        hex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
    );
    let plaintext = hex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    );
    assert_eq!(
        cipher::encrypt(&mut entry.cipher(), &params, &plaintext).unwrap(),
        hex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
             5bc94fbc3221a5db94fae95ae7121a47"
        )
    );
}

#[test]
fn aes_ocb_matches_the_rfc_7253_sample_without_associated_data() {
    let entry = cipher::get_by_name("AES/OCB/NOPADDING").unwrap();
    let params = AnyParams::aead(
        hex("000102030405060708090a0b0c0d0e0f"),
        128,
        hex("bbaa99887766554433221100"),
        Vec::new(),
    );
    // 空的明文只輸出 tag
    assert_eq!(
        cipher::encrypt(&mut entry.cipher(), &params, &[]).unwrap(),
        hex("785407bfffc8ad9edcc5520ac9111ee6")
    );
}

#[test]
fn a_tampered_aead_ciphertext_fails_to_decrypt() {
    for name in ["AES/CCM", "AES/EAX", "AES/GCM", "AES/OCB"] {
        let entry = cipher::get_by_name(name).unwrap();
        let params = AnyParams::aead(vec![7; 16], 128, vec![9; 12], Vec::new());
        let mut aes = entry.cipher();
        let mut sealed = cipher::encrypt(&mut aes, &params, b"attack at dawn").unwrap();
        sealed[0] ^= 1;
        assert!(
            cipher::decrypt(&mut aes, &params, &sealed).is_err(),
            "{name}"
        );
    }
}

#[test]
fn names_ignore_case_and_accept_bc_aliases_for_each_part() {
    assert_eq!(
        name_of("aes/cbc/pkcs7padding"),
        Ok("AES/CBC/PKCS7PADDING".into())
    );
    assert_eq!(name_of("AES/CBC/PKCS5"), Ok("AES/CBC/PKCS7PADDING".into()));
    assert_eq!(name_of("AES/SIC/NoPadding"), Ok("AES/CTR/NOPADDING".into()));
    assert_eq!(
        name_of("AES/CBC/ISO7816_4PADDING"),
        Ok("AES/CBC/ISO7816-4PADDING".into())
    );
    assert_eq!(
        name_of("AES/ECB/ISO10126-2PADDING"),
        Ok("AES/ECB/ISO10126PADDING".into())
    );
}

#[test]
fn a_missing_mode_or_padding_follows_the_bc_defaults() {
    assert_eq!(name_of("AES"), Ok("AES/ECB/PKCS7PADDING".into()));
    assert_eq!(name_of("AES//PKCS5"), Ok("AES/ECB/PKCS7PADDING".into()));
    assert_eq!(name_of("AES/CBC"), Ok("AES/CBC/PKCS7PADDING".into()));
    assert_eq!(name_of("AES/CFB"), Ok("AES/CFB/NOPADDING".into()));
    assert_eq!(name_of("AES/CTR/"), Ok("AES/CTR/NOPADDING".into()));
    assert_eq!(name_of("AES/GCM"), Ok("AES/GCM/NOPADDING".into()));
    assert_eq!(
        cipher::get(Algorithm::Aes, None, None).map(|entry| entry.name()),
        Ok("AES/ECB/PKCS7PADDING")
    );
    assert_eq!(
        cipher::get(Algorithm::Aes, Some(Mode::Ccm), None).map(|entry| entry.name()),
        Ok("AES/CCM/NOPADDING")
    );
}

#[test]
fn every_bc_aes_oid_maps_to_its_combination() {
    let groups = [
        (1, "AES/ECB/PKCS7PADDING"),
        (2, "AES/CBC/PKCS7PADDING"),
        (3, "AES/OFB/NOPADDING"),
        (4, "AES/CFB/NOPADDING"),
        (6, "AES/GCM/NOPADDING"),
        (7, "AES/CCM/NOPADDING"),
    ];
    for (arc, expected) in groups {
        // 128、192、256 bits 的 OID 各差 20
        for offset in [0, 20, 40] {
            let dotted = format!("2.16.840.1.101.3.4.1.{}", arc + offset);
            assert_eq!(name_of(&dotted), Ok(expected.into()), "{dotted}");
            assert_eq!(
                cipher::get_by_oid(&dotted.parse().unwrap()).map(|entry| entry.name()),
                Ok(expected),
                "{dotted}"
            );
        }
    }
}

#[test]
fn invalid_or_unknown_names_are_rejected() {
    for name in [
        "AES/GCM/PKCS7PADDING",
        "AES/CCM/ZEROBYTEPADDING",
        "BLOWFISH/CBC/PKCS7PADDING",
        "AES/XTS/NOPADDING",
        "AES/CBC/OAEP",
        "AES/CBC/PKCS7PADDING/EXTRA",
        "AES/CFB8/NOPADDING",
        "2.16.840.1.101.3.4.1.5",
        "",
    ] {
        assert_eq!(name_of(name), Err(SecurityError::UnknownCipher), "{name:?}");
    }
    assert_eq!(
        cipher::get(Algorithm::Aes, Some(Mode::Gcm), Some(Padding::Pkcs7)).err(),
        Some(SecurityError::UnknownCipher)
    );
}

#[test]
fn an_entry_displays_its_name_followed_by_its_oid_names() {
    assert_eq!(
        cipher::get_by_name("AES/CCM").unwrap().to_string(),
        "AES/CCM/NOPADDING  [id-aes128-CCM, id-aes192-CCM, id-aes256-CCM]"
    );
    assert_eq!(
        cipher::get_by_name("AES/CBC/NOPADDING")
            .unwrap()
            .to_string(),
        "AES/CBC/NOPADDING"
    );
}

#[test]
fn init_rejects_lengths_the_combination_cannot_use() {
    let rejects = |name: &str, params: AnyParams| {
        let entry = cipher::get_by_name(name).unwrap();
        cipher::encrypt(&mut entry.cipher(), &params, &[0; 16]).is_err()
    };
    let key = || vec![0; 16];
    assert!(rejects(
        "AES/CBC/PKCS7PADDING",
        AnyParams::new(vec![0; 20]).with_iv(vec![0; 16])
    ));
    assert!(rejects(
        "AES/CBC/PKCS7PADDING",
        AnyParams::new(key()).with_iv(vec![0; 12])
    ));
    // CBC 要 IV：只給金鑰不夠
    assert!(rejects("AES/CBC/PKCS7PADDING", AnyParams::new(key())));
    assert!(rejects(
        "AES/CCM",
        AnyParams::aead(key(), 128, vec![0; 14], Vec::new())
    ));
    // tag 長度以 bit 計：CCM 不接受 40 bits，接受 64 bits
    assert!(rejects(
        "AES/CCM",
        AnyParams::aead(key(), 40, vec![0; 12], Vec::new())
    ));
    assert!(!rejects(
        "AES/CCM",
        AnyParams::aead(key(), 64, vec![0; 12], Vec::new())
    ));
    assert!(rejects(
        "AES/GCM",
        AnyParams::aead(key(), 136, vec![0; 12], Vec::new())
    ));
    assert!(rejects(
        "AES/OCB",
        AnyParams::aead(key(), 128, vec![0; 16], Vec::new())
    ));
}

#[test]
fn decrypting_with_a_wrong_key_fails_the_padding_check_or_the_tag() {
    let cbc = |key| AnyParams::new(key).with_iv(vec![9; 16]);
    let gcm = |key| AnyParams::aead(key, 128, vec![9; 12], Vec::new());
    for (name, params) in [
        ("AES/CBC/PKCS7PADDING", cbc as fn(Vec<u8>) -> AnyParams),
        ("AES/GCM", gcm),
    ] {
        let entry = cipher::get_by_name(name).unwrap();
        let mut aes = entry.cipher();
        let sealed = cipher::encrypt(&mut aes, &params(vec![1; 16]), &[0x5a; 16]).unwrap();

        let wrong = params(vec![2; 16]);
        // CBC 有 1/256 左右的機率剛好解出合法的 padding，所以只比較結果不等於原文
        let opened = cipher::decrypt(&mut aes, &wrong, &sealed);
        assert!(opened.map_or(true, |plain| plain != [0x5a; 16]), "{name}");
    }
}

#[test]
fn an_aead_mode_rejects_a_key_and_iv_without_a_tag_size() {
    // 沒給 tag 長度就要靠預設值，而各模式、各函式庫的預設不同：一律要求 AEAD 的參數
    for name in ["AES/CCM", "AES/EAX", "AES/GCM", "AES/OCB"] {
        let entry = cipher::get_by_name(name).unwrap();
        let params = AnyParams::new(vec![7; 16]).with_iv(vec![9; 12]);
        assert!(
            cipher::encrypt(&mut entry.cipher(), &params, b"attack at dawn").is_err(),
            "{name}"
        );
    }
}
