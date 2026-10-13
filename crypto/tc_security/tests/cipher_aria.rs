//! cipher 工廠的 ARIA：RFC 5794 的已知答案與 BC 的 NSRI OID。

#![cfg(feature = "aria")]

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

#[test]
fn aria_matches_the_rfc_5794_vectors() {
    // 附錄 A.1 到 A.3：同一個明文，三種金鑰長度
    let plaintext = hex("00112233445566778899aabbccddeeff");
    let entry = cipher::get_by_name("ARIA/ECB/NOPADDING").unwrap();
    for (key, expected) in [
        (
            "000102030405060708090a0b0c0d0e0f",
            "d718fbd6ab644c739da95f3be6451778",
        ),
        (
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "26449c1805dbe7aa25a468ce263a9e79",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "f92bd7c79fb72e2f2b8f80c1972d24fc",
        ),
    ] {
        let params = AnyParams::new(hex(key));
        assert_eq!(
            cipher::encrypt(&mut entry.cipher(), &params, &plaintext).unwrap(),
            hex(expected),
            "{key}"
        );
    }
}

#[test]
fn every_bc_aria_oid_maps_to_its_combination() {
    // 128、192、256 bits 的 OID 依序排在一起
    let groups = [
        ([1, 6, 11], "ARIA/ECB/PKCS7PADDING"),
        ([2, 7, 12], "ARIA/CBC/PKCS7PADDING"),
        ([3, 8, 13], "ARIA/CFB/NOPADDING"),
        ([4, 9, 14], "ARIA/OFB/NOPADDING"),
        ([5, 10, 15], "ARIA/CTR/NOPADDING"),
        ([34, 35, 36], "ARIA/GCM/NOPADDING"),
        ([37, 38, 39], "ARIA/CCM/NOPADDING"),
    ];
    for (arcs, expected) in groups {
        for arc in arcs {
            let dotted = format!("1.2.410.200046.1.1.{arc}");
            assert_eq!(name_of(&dotted), Ok(expected.into()), "{dotted}");
        }
    }
}
