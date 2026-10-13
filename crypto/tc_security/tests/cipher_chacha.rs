//! cipher 工廠的 ChaCha 系列 stream cipher：已知答案、名稱規則與 `init` 對參數的檢查。

#![cfg(feature = "chacha")]

use tc_security::SecurityError;
use tc_security::cipher::{self, Algorithm, Mode};
use tc_security::params::AnyParams;

fn hex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn name_of(name: &str) -> Result<String, SecurityError> {
    cipher::get_by_name(name).map(|entry| entry.name().to_string())
}

// RFC 8439 附錄 A.1 測試向量 1：全零的金鑰與 nonce，從第 0 個區塊開始的金鑰串流
const ZERO_KEYSTREAM: &str = "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7
                              da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586";

#[test]
fn chacha7539_matches_the_rfc_8439_appendix_a1_keystream() {
    let entry = cipher::get_by_name("CHACHA7539").unwrap();
    let params = AnyParams::new(vec![0; 32]).with_iv(vec![0; 12]);
    assert_eq!(
        cipher::encrypt(&mut entry.cipher(), &params, &[0; 64]).unwrap(),
        hex(ZERO_KEYSTREAM)
    );
}

#[test]
fn the_original_chacha_gives_the_same_first_block_for_a_zero_key_and_nonce() {
    // 計數器與 nonce 全為零時，原版與 RFC 8439 的初始狀態相同
    let entry = cipher::get_by_name("CHACHA").unwrap();
    let params = AnyParams::new(vec![0; 32]).with_iv(vec![0; 8]);
    assert_eq!(
        cipher::encrypt(&mut entry.cipher(), &params, &[0; 64]).unwrap(),
        hex(ZERO_KEYSTREAM)
    );
}

#[test]
fn xchacha20_matches_the_draft_encryption_example() {
    // 草案的範例從第 1 個區塊開始加密，所以前面墊一個區塊的零再丟掉
    let entry = cipher::get_by_name("XCHACHA20").unwrap();
    let params = AnyParams::new(hex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    ))
    .with_iv(hex("404142434445464748494a4b4c4d4e4f5051525354555657"));
    let mut input = vec![0; 64];
    input.extend(hex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173
         73206f66202739393a204966204920636f756c64206f6666657220796f75206f
         6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73
         637265656e20776f756c642062652069742e",
    ));
    let output = cipher::encrypt(&mut entry.cipher(), &params, &input).unwrap();
    assert_eq!(
        output[64..],
        hex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
             21f9664c97637da9768812f615c68b13b52e"
        )
    );
}

#[test]
fn a_stream_cipher_is_named_without_a_mode_or_padding() {
    assert_eq!(name_of("chacha"), Ok("CHACHA".into()));
    assert_eq!(name_of("CHACHA20"), Ok("CHACHA7539".into()));
    assert_eq!(name_of("XChaCha20"), Ok("XCHACHA20".into()));

    let entry = cipher::get(Algorithm::ChaCha, None, None).unwrap();
    assert_eq!((entry.mode(), entry.padding()), (None, None));
    assert_eq!(entry.to_string(), "CHACHA");
}

#[test]
fn a_stream_cipher_rejects_any_mode_or_padding() {
    // 同 BC：stream cipher 的名稱帶了 `/` 就不認
    for name in [
        "CHACHA/ECB",
        "CHACHA//",
        "CHACHA/ECB/NOPADDING",
        "CHACHA7539/CTR",
    ] {
        assert_eq!(name_of(name), Err(SecurityError::UnknownCipher), "{name}");
    }
    assert_eq!(
        cipher::get(Algorithm::ChaCha, Some(Mode::Ecb), None).err(),
        Some(SecurityError::UnknownCipher)
    );
}

#[test]
fn init_rejects_lengths_the_variant_cannot_use() {
    let rejects = |name: &str, key: usize, nonce: usize| {
        let entry = cipher::get_by_name(name).unwrap();
        let params = AnyParams::new(vec![0; key]).with_iv(vec![0; nonce]);
        cipher::encrypt(&mut entry.cipher(), &params, &[0; 8]).is_err()
    };
    for (name, key, nonce) in [
        ("CHACHA", 16, 8),
        ("CHACHA", 32, 8),
        ("CHACHA7539", 32, 12),
        ("XCHACHA20", 32, 24),
    ] {
        assert!(!rejects(name, key, nonce), "{name}/{key}/{nonce}");
    }
    for (name, key, nonce) in [
        ("CHACHA", 24, 8),
        ("CHACHA", 32, 12),
        ("CHACHA7539", 16, 12),
        ("XCHACHA20", 32, 12),
    ] {
        assert!(rejects(name, key, nonce), "{name}/{key}/{nonce}");
    }
}
