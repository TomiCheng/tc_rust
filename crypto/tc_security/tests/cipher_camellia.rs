//! cipher、產生器與 key wrap 工廠的 Camellia：RFC 3713 的已知答案、BC 的 CamelliaWrap 向量與 NTT OID。

#![cfg(feature = "camellia")]

use tc_block_cipher::KeyParams;
use tc_security::generate::{self, KeyGenParams};
use tc_security::params::AnyParams;
use tc_security::{SecurityError, cipher, wrap};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn camellia_matches_the_rfc_3713_vectors() {
    // 附錄 A：同一個明文，三種金鑰長度
    let plaintext = hex("0123456789abcdeffedcba9876543210");
    let entry = cipher::get_by_name("CAMELLIA/ECB/NOPADDING").unwrap();
    for (key, expected) in [
        (
            "0123456789abcdeffedcba9876543210",
            "67673138549669730857065648eabe43",
        ),
        (
            "0123456789abcdeffedcba98765432100011223344556677",
            "b4993401b3e996f84ee5cee7d79b09b9",
        ),
        (
            "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
            "9acc237dff16d76c20ef7c919e3a7509",
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
fn every_ntt_cbc_oid_maps_to_camellia_cbc() {
    for arc in 2..=4 {
        let dotted = format!("1.2.392.200011.61.1.1.1.{arc}");
        assert_eq!(
            cipher::get_by_name(&dotted).map(|entry| entry.name().to_string()),
            Ok("CAMELLIA/CBC/PKCS7PADDING".to_string()),
            "{dotted}"
        );
    }
}

#[test]
fn camellia_keys_follow_the_bc_names_oids_and_sizes() {
    let name_of = |name: &str| generate::get_by_name(name).map(|entry| entry.name());
    assert_eq!(name_of("camelliawrap"), Ok("CAMELLIA"));
    for (arc, expected) in [(2, "CAMELLIA128"), (3, "CAMELLIA192"), (4, "CAMELLIA256")] {
        for branch in [1, 3] {
            let dotted = format!("1.2.392.200011.61.1.1.{branch}.{arc}");
            assert_eq!(name_of(&dotted), Ok(expected), "{dotted}");
        }
    }

    for (name, bytes) in [
        ("CAMELLIA", 32),
        ("CAMELLIA128", 16),
        ("CAMELLIA192", 24),
        ("CAMELLIA256", 32),
    ] {
        let key = generate::get_by_name(name)
            .unwrap()
            .generator()
            .generate_key()
            .unwrap();
        assert_eq!(KeyParams::key(&key).len(), bytes, "{name}");
    }

    let mut generator = generate::get_by_name("CAMELLIA").unwrap().generator();
    generator
        .init(&KeyGenParams::Basic { strength: 128 })
        .unwrap();
    assert_eq!(KeyParams::key(&generator.generate_key().unwrap()).len(), 16);
    assert_eq!(
        generator.init(&KeyGenParams::Basic { strength: 64 }),
        Err(SecurityError::InvalidKeyGenParams)
    );
}

#[test]
fn camelliawrap_matches_the_bc_vector_and_unwraps_it() {
    let entry = wrap::get_by_name("CAMELLIAWRAP").unwrap();
    let params = AnyParams::new(hex("000102030405060708090a0b0c0d0e0f"));
    let key = hex("00112233445566778899aabbccddeeff");
    let mut wrapper = entry.wrapper();
    let wrapped = wrap::wrap(&mut wrapper, &params, &key).unwrap();
    assert_eq!(
        wrapped,
        hex("635d6ac46eedebd3a7f4a06421a4cbd1746b24795ba2f708")
    );
    assert_eq!(wrap::unwrap(&mut wrapper, &params, &wrapped).unwrap(), key);
}

#[test]
fn every_ntt_wrap_oid_finds_camelliawrap() {
    for arc in 2..=4 {
        let dotted = format!("1.2.392.200011.61.1.1.3.{arc}");
        assert_eq!(
            wrap::get_by_name(&dotted).map(|entry| entry.name()),
            Ok("CAMELLIAWRAP"),
            "{dotted}"
        );
    }
}

#[test]
fn a_generated_camellia_key_works_with_the_cipher_factory() {
    let key = generate::get_by_name("CAMELLIA256")
        .unwrap()
        .generator()
        .generate_key()
        .unwrap();
    let params = key.with_iv(vec![9; 16]);
    let message = b"attack at dawn";
    let mut camellia = cipher::get_by_name("CAMELLIA/CBC/PKCS7PADDING")
        .unwrap()
        .cipher();
    let sealed = cipher::encrypt(&mut camellia, &params, message).unwrap();
    assert_eq!(
        cipher::decrypt(&mut camellia, &params, &sealed).unwrap(),
        message
    );
}
