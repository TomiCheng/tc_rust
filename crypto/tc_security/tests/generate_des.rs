//! DES 與 Triple DES 的產生器：BC 的名稱、OID 與長度，odd parity，弱金鑰與重複分段會重抽。

#![cfg(any(feature = "des", feature = "desede"))]

use std::convert::Infallible;

use rand::{TryCryptoRng, TryRng};
use tc_block_cipher::KeyParams;
use tc_security::SecurityError;
use tc_security::generate::{self, KeyGenParams};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn name_of(name: &str) -> Result<&'static str, SecurityError> {
    generate::get_by_name(name).map(|entry| entry.name())
}

fn has_odd_parity(key: &[u8]) -> bool {
    key.iter().all(|byte| byte.count_ones() % 2 == 1)
}

/// 每次填位元組時依序交出下一段，用來讓產生器先抽到弱金鑰。
struct ScriptedRng(std::vec::IntoIter<Vec<u8>>);

impl ScriptedRng {
    fn new(draws: &[&str]) -> Self {
        Self(
            draws
                .iter()
                .map(|draw| hex(draw))
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }
}

impl TryRng for ScriptedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        unreachable!("the DES generators only fill bytes")
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        unreachable!("the DES generators only fill bytes")
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Infallible> {
        output.copy_from_slice(&self.0.next().expect("a scripted draw is left"));
        Ok(())
    }
}

impl TryCryptoRng for ScriptedRng {}

#[cfg(feature = "des")]
#[test]
fn des_keys_are_8_bytes_with_odd_parity_and_never_weak() {
    for oid in [
        "1.3.14.3.2.6",
        "1.3.14.3.2.7",
        "1.3.14.3.2.8",
        "1.3.14.3.2.9",
    ] {
        assert_eq!(name_of(oid), Ok("DES"), "{oid}");
    }

    let mut generator = generate::get_by_name("DES").unwrap().generator();
    for strength in [None, Some(56), Some(64)] {
        if let Some(strength) = strength {
            generator.init(&KeyGenParams::Basic { strength }).unwrap();
        }
        let key = generator.generate_key().unwrap();
        let key = KeyParams::key(&key);
        assert_eq!(key.len(), 8, "{strength:?}");
        assert!(has_odd_parity(key), "{strength:?}");
        assert!(
            !tc_des::is_weak_key(key.try_into().unwrap()),
            "{strength:?}"
        );
    }
    for strength in [0, 48, 128] {
        assert_eq!(
            generator.init(&KeyGenParams::Basic { strength }),
            Err(SecurityError::InvalidKeyGenParams),
            "{strength}"
        );
    }
}

#[cfg(feature = "des")]
#[test]
fn a_des_generator_draws_again_after_a_weak_key_and_fixes_parity() {
    let mut generator = generate::get_by_name("DES").unwrap().generator();
    generator.with_rng(ScriptedRng::new(&[
        // 弱金鑰，parity 正確
        "0101010101010101",
        // 半弱金鑰，parity 全錯：設好 parity 後才認得出來
        "00ff00ff00ff00ff",
        // 一般金鑰，parity 全錯
        "0022446688aaccee",
    ]));
    let key = generator.generate_key().unwrap();
    assert_eq!(KeyParams::key(&key), hex("0123456789abcdef"));
}

#[cfg(feature = "desede")]
#[test]
fn triple_des_keys_follow_the_bc_names_and_sizes() {
    for (name, expected) in [
        ("TDEA", "DESEDE"),
        ("desedewrap", "DESEDE"),
        ("1.3.14.3.2.17", "DESEDE"),
        ("1.2.840.113549.3.7", "DESEDE3"),
        ("1.2.840.113549.1.9.16.3.6", "DESEDE3"),
    ] {
        assert_eq!(name_of(name), Ok(expected), "{name}");
    }

    for (name, bytes) in [("DESEDE", 16), ("DESEDE3", 24)] {
        let mut generator = generate::get_by_name(name).unwrap().generator();
        assert_eq!(
            KeyParams::key(&generator.generate_key().unwrap()).len(),
            bytes,
            "{name}"
        );
        for (strength, bytes) in [(112, 16), (128, 16), (168, 24), (192, 24)] {
            generator.init(&KeyGenParams::Basic { strength }).unwrap();
            let key = generator.generate_key().unwrap();
            let key = KeyParams::key(&key);
            assert_eq!(key.len(), bytes, "{name}/{strength}");
            assert!(has_odd_parity(key), "{name}/{strength}");
            assert!(!tc_des::is_weak_ede_key(key), "{name}/{strength}");
            assert!(tc_des::is_real_ede_key(key), "{name}/{strength}");
        }
        for strength in [64, 256] {
            assert_eq!(
                generator.init(&KeyGenParams::Basic { strength }),
                Err(SecurityError::InvalidKeyGenParams),
                "{name}/{strength}"
            );
        }
    }
}

#[cfg(feature = "desede")]
#[test]
fn a_triple_des_generator_draws_again_after_a_weak_or_repeated_part() {
    let mut two_key = generate::get_by_name("DESEDE").unwrap().generator();
    two_key.with_rng(ScriptedRng::new(&[
        // K1 = K2：退化成單 DES
        "0123456789abcdef0123456789abcdef",
        // K2 只差 parity，設好 parity 後也一樣
        "0123456789abcdef0022446688aaccee",
        // K2 是弱金鑰
        "0123456789abcdeffefefefefefefefe",
        "0123456789abcdeffedcba9876543210",
    ]));
    assert_eq!(
        KeyParams::key(&two_key.generate_key().unwrap()),
        hex("0123456789abcdeffedcba9876543210")
    );

    let mut three_key = generate::get_by_name("DESEDE3").unwrap().generator();
    three_key.with_rng(ScriptedRng::new(&[
        // K1 = K3
        "0123456789abcdef23456789abcdef010123456789abcdef",
        "0123456789abcdef23456789abcdef01456789abcdef0123",
    ]));
    assert_eq!(
        KeyParams::key(&three_key.generate_key().unwrap()),
        hex("0123456789abcdef23456789abcdef01456789abcdef0123")
    );
}

#[cfg(feature = "desede")]
#[test]
fn a_generated_triple_des_key_works_with_the_cipher_factory() {
    use tc_security::cipher;

    let key = generate::get_by_name("DESEDE3")
        .unwrap()
        .generator()
        .generate_key()
        .unwrap();
    let params = key.with_iv(vec![9; 8]);
    let message = b"attack at dawn";
    let mut desede = cipher::get_by_name("DESEDE/CBC/PKCS7PADDING")
        .unwrap()
        .cipher();
    let sealed = cipher::encrypt(&mut desede, &params, message).unwrap();
    assert_eq!(
        cipher::decrypt(&mut desede, &params, &sealed).unwrap(),
        message
    );
}
