//! key wrap 工廠：RFC 3394 的已知答案、名稱與 OID 查詢，以及 IV 的用法。

#![cfg(feature = "aes")]

use tc_security::SecurityError;
use tc_security::params::AnyParams;
use tc_security::wrap;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn aeswrap_matches_the_rfc_3394_vectors() {
    // 4.1、4.2 與 4.6：不同長度的 KEK 包住 16 或 32 bytes 的金鑰
    let entry = wrap::get_by_name("AESWRAP").unwrap();
    for (kek, key, expected) in [
        (
            "000102030405060708090A0B0C0D0E0F",
            "00112233445566778899AABBCCDDEEFF",
            "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
        ),
        (
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "00112233445566778899AABBCCDDEEFF",
            "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
        ),
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        ),
    ] {
        let params = AnyParams::new(hex(kek));
        let mut wrapper = entry.wrapper();
        let wrapped = wrap::wrap(&mut wrapper, &params, &hex(key)).unwrap();
        assert_eq!(wrapped, hex(expected), "{kek}");
        assert_eq!(
            wrap::unwrap(&mut wrapper, &params, &wrapped).unwrap(),
            hex(key)
        );
    }
}

#[test]
fn a_tampered_wrapped_key_fails_the_integrity_check() {
    let entry = wrap::get_by_name("AESWRAP").unwrap();
    let params = AnyParams::new(vec![7; 16]);
    let mut wrapper = entry.wrapper();
    let mut wrapped = wrap::wrap(&mut wrapper, &params, &[0x24; 16]).unwrap();
    wrapped[0] ^= 1;
    assert!(wrap::unwrap(&mut wrapper, &params, &wrapped).is_err());
}

#[test]
fn names_aliases_and_bc_oids_find_aeswrap() {
    for name in [
        "AESWRAP",
        "aeskw",
        "2.16.840.1.101.3.4.1.5",
        "2.16.840.1.101.3.4.1.25",
        "2.16.840.1.101.3.4.1.45",
    ] {
        assert_eq!(
            wrap::get_by_name(name).map(|entry| entry.name()),
            Ok("AESWRAP"),
            "{name}"
        );
    }
    let oid = "2.16.840.1.101.3.4.1.25".parse().unwrap();
    assert_eq!(
        wrap::get_by_oid(&oid).map(|entry| entry.name()),
        Ok("AESWRAP")
    );
    assert_eq!(
        wrap::get_by_name("AESWRAPPAD").err(),
        Some(SecurityError::UnknownWrapper)
    );
}

#[test]
fn an_entry_displays_its_name_followed_by_its_oid_names() {
    assert_eq!(
        wrap::get_by_name("AESWRAP").unwrap().to_string(),
        "AESWRAP  [id-aes128-wrap, id-aes192-wrap, id-aes256-wrap]"
    );
}

#[test]
fn a_kek_alone_uses_the_rfc_default_iv() {
    // 沒帶 IV 時兩端都用規格的 A6A6…，跟明確給 A6A6… 的結果相同
    let entry = wrap::get_by_name("AESWRAP").unwrap();
    let mut wrapper = entry.wrapper();
    let alone = wrap::wrap(&mut wrapper, &AnyParams::new(vec![7; 16]), &[0x24; 16]).unwrap();
    let explicit = AnyParams::new(vec![7; 16]).with_iv(vec![0xa6; 8]);
    assert_eq!(
        wrap::wrap(&mut wrapper, &explicit, &[0x24; 16]).unwrap(),
        alone
    );
}

#[test]
fn a_custom_iv_must_be_eight_bytes_and_must_match_on_unwrap() {
    let entry = wrap::get_by_name("AESWRAP").unwrap();
    let mut wrapper = entry.wrapper();
    let short = AnyParams::new(vec![7; 16]).with_iv(vec![0; 4]);
    assert!(wrap::wrap(&mut wrapper, &short, &[0x24; 16]).is_err());

    let custom = AnyParams::new(vec![7; 16]).with_iv(vec![0x5a; 8]);
    let wrapped = wrap::wrap(&mut wrapper, &custom, &[0x24; 16]).unwrap();
    assert_eq!(
        wrap::unwrap(&mut wrapper, &custom, &wrapped).unwrap(),
        [0x24; 16]
    );

    // 用預設 IV 解不開
    let default_iv = AnyParams::new(vec![7; 16]);
    assert!(wrap::unwrap(&mut wrapper, &default_iv, &wrapped).is_err());
}

#[test]
fn init_rejects_a_kek_aes_cannot_use() {
    let entry = wrap::get_by_name("AESWRAP").unwrap();
    let params = AnyParams::new(vec![0; 20]);
    assert!(wrap::wrap(&mut entry.wrapper(), &params, &[0x24; 16]).is_err());
}
