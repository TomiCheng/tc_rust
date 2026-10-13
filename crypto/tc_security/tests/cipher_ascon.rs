//! cipher 工廠的 Ascon AEAD（預設不開的 `ascon` feature）：官方 KAT、名稱規則與 `init` 對參數的檢查。

#![cfg(feature = "ascon")]

use tc_security::SecurityError;
use tc_security::cipher::{self, Algorithm, Mode};
use tc_security::params::AnyParams;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn encrypt(name: &str, key: &str, nonce: &str, plaintext: &str) -> Vec<u8> {
    let entry = cipher::get_by_name(name).unwrap();
    let params = AnyParams::aead(hex(key), 128, hex(nonce), Vec::new());
    cipher::encrypt(&mut entry.cipher(), &params, &hex(plaintext)).unwrap()
}

#[test]
fn ascon_aead128_matches_the_ascon_c_kats_without_associated_data() {
    let (key, nonce) = (
        "000102030405060708090A0B0C0D0E0F",
        "101112131415161718191A1B1C1D1E1F",
    );
    assert_eq!(
        encrypt("ASCON-AEAD128", key, nonce, ""),
        hex("4F9C278211BEC9316BF68F46EE8B2EC6")
    );
    assert_eq!(
        encrypt("ASCON-AEAD128", key, nonce, "2021222324252627"),
        hex("E8C3DEEE246CC5EAE455EF6B33B782A3DD91ED6695373C27")
    );
}

#[test]
fn the_ascon_v1_2_variants_match_their_empty_message_kats() {
    let nonce = "000102030405060708090A0B0C0D0E0F";
    let key_128 = "000102030405060708090A0B0C0D0E0F";
    for (name, key, tag) in [
        ("ASCON-128", key_128, "E355159F292911F794CB1432A0103A8A"),
        ("ASCON-128A", key_128, "7A834E6F09210957067B10FD831F0078"),
        (
            "ASCON-80PQ",
            "000102030405060708090A0B0C0D0E0F10111213",
            "ABB688EFA0B9D56B33277A2C97D2146B",
        ),
    ] {
        assert_eq!(encrypt(name, key, nonce, ""), hex(tag), "{name}");
    }
}

#[test]
fn a_tampered_ascon_ciphertext_fails_to_decrypt() {
    for name in ["ASCON-AEAD128", "ASCON-128", "ASCON-128A", "ASCON-80PQ"] {
        let entry = cipher::get_by_name(name).unwrap();
        let key = if name == "ASCON-80PQ" { 20 } else { 16 };
        let params = AnyParams::aead(vec![7; key], 128, vec![9; 16], Vec::new());
        let mut ascon = entry.cipher();
        let mut sealed = cipher::encrypt(&mut ascon, &params, b"attack at dawn").unwrap();
        sealed[0] ^= 1;
        assert!(
            cipher::decrypt(&mut ascon, &params, &sealed).is_err(),
            "{name}"
        );
    }
}

#[test]
fn ascon_is_named_without_a_mode_or_padding() {
    assert_eq!(
        cipher::get_by_name("ascon-aead128").map(|entry| entry.name()),
        Ok("ASCON-AEAD128")
    );
    assert_eq!(
        cipher::get_by_name("ASCON-AEAD128/GCM").err(),
        Some(SecurityError::UnknownCipher)
    );
    assert_eq!(
        cipher::get(Algorithm::AsconAead128, Some(Mode::Ecb), None).err(),
        Some(SecurityError::UnknownCipher)
    );
    let entry = cipher::get(Algorithm::Ascon80pq, None, None).unwrap();
    assert_eq!((entry.mode(), entry.padding()), (None, None));
}

#[test]
fn init_checks_the_ascon_key_and_tag_size() {
    let rejects = |name: &str, params: AnyParams| {
        let entry = cipher::get_by_name(name).unwrap();
        cipher::encrypt(&mut entry.cipher(), &params, b"message").is_err()
    };
    // Ascon-AEAD128 的 tag 可以截短到 4 bytes（32 bits），再短就不行
    assert!(!rejects(
        "ASCON-AEAD128",
        AnyParams::aead(vec![0; 16], 32, vec![0; 16], Vec::new())
    ));
    assert!(rejects(
        "ASCON-AEAD128",
        AnyParams::aead(vec![0; 16], 24, vec![0; 16], Vec::new())
    ));
    // v1.2 的 tag 固定 16 bytes
    assert!(rejects(
        "ASCON-128",
        AnyParams::aead(vec![0; 16], 64, vec![0; 16], Vec::new())
    ));
    assert!(rejects(
        "ASCON-80PQ",
        AnyParams::aead(vec![0; 16], 128, vec![0; 16], Vec::new())
    ));
}

#[test]
fn an_ascon_engine_refuses_to_seal_twice_under_one_nonce() {
    // 引擎拒絕同一組金鑰與 nonce 再加密；每則訊息要換新的 nonce
    let entry = cipher::get_by_name("ASCON-AEAD128").unwrap();
    let mut ascon = entry.cipher();

    let first = AnyParams::aead(vec![7; 16], 128, vec![1; 16], Vec::new());
    cipher::encrypt(&mut ascon, &first, b"one").unwrap();
    assert!(cipher::encrypt(&mut ascon, &first, b"two").is_err());

    let second = AnyParams::aead(vec![7; 16], 128, vec![2; 16], Vec::new());
    assert!(cipher::encrypt(&mut ascon, &second, b"two").is_ok());
}
