//! key wrap 工廠的 ARIAWRAP：沒有公開的向量，所以在這裡照 RFC 3394 的演算法用 ARIA/ECB 一塊一塊算出預期值比對。

#![cfg(feature = "aria")]

use tc_security::cipher;
use tc_security::params::AnyParams;
use tc_security::wrap;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 3394 第 2.2.1 節的 wrap，以 `cipher_name` 的 ECB 加密一個 16 bytes 區塊當作 W 的內層函式。
fn rfc3394_wrap(cipher_name: &str, kek: &[u8], key: &[u8]) -> Vec<u8> {
    let entry = cipher::get_by_name(cipher_name).unwrap();
    let params = AnyParams::new(kek.to_vec());
    let mut ecb = entry.cipher();

    let mut a = [0xa6; 8];
    let mut r: Vec<[u8; 8]> = key.chunks(8).map(|c| c.try_into().unwrap()).collect();
    let n = r.len();
    for j in 0..6 {
        for (i, ri) in r.iter_mut().enumerate() {
            let mut block = [0; 16];
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(ri);
            let b = cipher::encrypt(&mut ecb, &params, &block).unwrap();
            let t = (n * j + i + 1) as u64;
            for (k, byte) in a.iter_mut().enumerate() {
                *byte = b[k] ^ t.to_be_bytes()[k];
            }
            ri.copy_from_slice(&b[8..]);
        }
    }
    let mut out = a.to_vec();
    for block in r {
        out.extend(block);
    }
    out
}

#[cfg(feature = "aes")]
#[test]
fn the_reference_wrap_reproduces_the_rfc_3394_aes_vector() {
    // 先確認上面的參考實作本身沒錯：用 AES 算出 RFC 3394 第 4.1 節的答案
    assert_eq!(
        rfc3394_wrap(
            "AES/ECB/NOPADDING",
            &hex("000102030405060708090A0B0C0D0E0F"),
            &hex("00112233445566778899AABBCCDDEEFF"),
        ),
        hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    );
}

#[test]
fn ariawrap_matches_rfc_3394_computed_with_aria_ecb() {
    let entry = wrap::get_by_name("ARIAWRAP").unwrap();
    for (kek, key) in [
        (
            "000102030405060708090A0B0C0D0E0F",
            "00112233445566778899AABBCCDDEEFF",
        ),
        (
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "00112233445566778899AABBCCDDEEFF0001020304050607",
        ),
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
        ),
    ] {
        let params = AnyParams::new(hex(kek));
        let mut wrapper = entry.wrapper();
        let wrapped = wrap::wrap(&mut wrapper, &params, &hex(key)).unwrap();
        assert_eq!(
            wrapped,
            rfc3394_wrap("ARIA/ECB/NOPADDING", &hex(kek), &hex(key)),
            "{kek}"
        );
        assert_eq!(
            wrap::unwrap(&mut wrapper, &params, &wrapped).unwrap(),
            hex(key)
        );
    }
}

#[test]
fn names_aliases_and_bc_oids_find_ariawrap() {
    for name in [
        "ARIAWRAP",
        "ariakw",
        "1.2.410.200046.1.1.40",
        "1.2.410.200046.1.1.41",
        "1.2.410.200046.1.1.42",
    ] {
        assert_eq!(
            wrap::get_by_name(name).map(|entry| entry.name()),
            Ok("ARIAWRAP"),
            "{name}"
        );
    }
}

#[test]
fn a_tampered_aria_wrapped_key_fails_the_integrity_check() {
    let entry = wrap::get_by_name("ARIAWRAP").unwrap();
    let params = AnyParams::new(vec![7; 32]);
    let mut wrapper = entry.wrapper();
    let mut wrapped = wrap::wrap(&mut wrapper, &params, &[0x24; 24]).unwrap();
    wrapped[10] ^= 1;
    assert!(wrap::unwrap(&mut wrapper, &params, &wrapped).is_err());
}
