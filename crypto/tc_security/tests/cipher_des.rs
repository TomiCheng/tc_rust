//! cipher 工廠的 DES 與 Triple DES：已知答案、BC 的 OID 與別名。

#![cfg(any(feature = "des", feature = "desede"))]

use tc_security::SecurityError;
use tc_security::cipher;
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

#[cfg(feature = "des")]
#[test]
fn des_matches_the_textbook_vector() {
    let entry = cipher::get_by_name("DES/ECB/NOPADDING").unwrap();
    let params = AnyParams::new(hex("133457799bbcdff1"));
    assert_eq!(
        cipher::encrypt(&mut entry.cipher(), &params, &hex("0123456789abcdef")).unwrap(),
        hex("85e813540f0ab405")
    );
}

#[cfg(feature = "des")]
#[test]
fn every_bc_des_oid_maps_to_its_combination() {
    for (oid, expected) in [
        ("1.3.14.3.2.6", "DES/ECB/PKCS7PADDING"),
        ("1.3.14.3.2.7", "DES/CBC/PKCS7PADDING"),
        ("1.3.14.3.2.8", "DES/OFB/NOPADDING"),
        ("1.3.14.3.2.9", "DES/CFB/NOPADDING"),
    ] {
        assert_eq!(name_of(oid).as_deref(), Ok(expected), "{oid}");
    }
}

#[cfg(feature = "desede")]
#[test]
fn triple_des_matches_the_two_key_and_three_key_vectors() {
    let entry = cipher::get_by_name("DESEDE/ECB/NOPADDING").unwrap();
    for (key, plaintext, expected) in [
        (
            "0123456789abcdeffedcba9876543210",
            "4e6f77206973207468652074696d6520666f7220616c6c20",
            "d80a0d8b2bae5e4e6a0094171abcfc2775d2235a706e232c",
        ),
        (
            "0123456789abcdef23456789abcdef01456789abcdef0123",
            "fedcba9876543210",
            "0737f6c53750d4a4",
        ),
    ] {
        let params = AnyParams::new(hex(key));
        assert_eq!(
            cipher::encrypt(&mut entry.cipher(), &params, &hex(plaintext)).unwrap(),
            hex(expected),
            "{key}"
        );
    }
}

#[cfg(feature = "desede")]
#[test]
fn triple_des_is_found_by_tdea_and_by_both_bc_oids() {
    assert_eq!(
        name_of("TDEA/CBC/PKCS7PADDING").as_deref(),
        Ok("DESEDE/CBC/PKCS7PADDING")
    );
    assert_eq!(
        name_of("1.3.14.3.2.17").as_deref(),
        Ok("DESEDE/ECB/PKCS7PADDING")
    );
    assert_eq!(
        name_of("1.2.840.113549.3.7").as_deref(),
        Ok("DESEDE/CBC/PKCS7PADDING")
    );
}

#[cfg(feature = "desede")]
#[test]
fn triple_des_rejects_keys_other_than_16_or_24_bytes() {
    let entry = cipher::get_by_name("DESEDE/ECB/NOPADDING").unwrap();
    for len in [8, 20, 32] {
        let params = AnyParams::new(vec![7; len]);
        assert!(
            cipher::encrypt(&mut entry.cipher(), &params, &[0; 8]).is_err(),
            "{len}"
        );
    }
}
