#![cfg(feature = "aes")]

use std::sync::LazyLock;

use tc_algo_old::{Algo, AnyKeyParams, AnyParams, CipherDirection, CipherEntry, ErrorKind, SecretKey};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

// The other block ciphers' rows are there too when their features are on
fn aes_entries() -> impl Iterator<Item = &'static CipherEntry> {
    ALGO.cipher()
        .algorithms()
        .filter(|entry| entry.name().starts_with("AES/"))
}

fn params(key: &str, iv: Option<&str>) -> AnyParams {
    let mut params = AnyParams::new(AnyKeyParams::Secret(SecretKey::new(hex(key))));
    params.op.iv = iv.map(hex);
    params
}

fn aead_params(key: &str, nonce: &str, tag_len: usize) -> AnyParams {
    let mut params = params(key, Some(nonce));
    params.op.tag_len = Some(tag_len);
    params
}

#[test]
fn ecb_without_padding_gives_the_fips_197_vector() {
    let params = params("000102030405060708090a0b0c0d0e0f", None);
    let output = ALGO
        .cipher()
        .encrypt(
            "AES/ECB/NOPADDING",
            &params,
            &hex("00112233445566778899aabbccddeeff"),
        )
        .unwrap();
    assert_eq!(output, hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
}

#[test]
fn the_modes_without_padding_give_the_sp_800_38a_vectors() {
    let key = "2b7e151628aed2a6abf7158809cf4f3c";
    let plaintext = hex("6bc1bee22e409f96e93d7e117393172a");
    for (name, iv, ciphertext) in [
        (
            "AES/CBC/NOPADDING",
            "000102030405060708090a0b0c0d0e0f",
            "7649abac8119b246cee98e9b12e9197d",
        ),
        (
            "AES/CFB/NOPADDING",
            "000102030405060708090a0b0c0d0e0f",
            "3b3fd92eb72dad20333449f8e83cfb4a",
        ),
        (
            "AES/OFB/NOPADDING",
            "000102030405060708090a0b0c0d0e0f",
            "3b3fd92eb72dad20333449f8e83cfb4a",
        ),
        (
            "AES/CTR/NOPADDING",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "874d6191b620e3261bef6864990db6ce",
        ),
    ] {
        let params = params(key, Some(iv));
        let output = ALGO.cipher().encrypt(name, &params, &plaintext).unwrap();
        assert_eq!(output, hex(ciphertext), "{name}");
        assert_eq!(
            ALGO.cipher().decrypt(name, &params, &output).unwrap(),
            plaintext
        );
    }
}

#[test]
fn gcm_gives_the_ciphertext_and_tag_of_the_gcm_specification() {
    let params = aead_params(
        "00000000000000000000000000000000",
        "000000000000000000000000",
        16,
    );
    let output = ALGO
        .cipher()
        .encrypt("AES/GCM/NOPADDING", &params, &[0; 16])
        .unwrap();
    assert_eq!(
        output,
        hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
    );
}

#[test]
fn every_combination_decrypts_what_it_encrypts() {
    let message: Vec<u8> = (1..=37).collect();
    for entry in aes_entries() {
        let mut parts = entry.name().split('/');
        let (mode, padding) = (parts.nth(1).unwrap(), parts.next().unwrap());
        let key = "000102030405060708090a0b0c0d0e0f";
        let params = match mode {
            "ECB" => params(key, None),
            "CCM" | "EAX" | "GCM" | "OCB" => aead_params(key, "101112131415161718191a1b", 16),
            _ => params(key, Some("101112131415161718191a1b1c1d1e1f")),
        };
        // ECB and CBC take whole blocks when nothing pads them
        let message = match (mode, padding) {
            ("ECB" | "CBC", "NOPADDING") => &message[..32],
            _ => &message[..],
        };
        let ciphertext = ALGO
            .cipher()
            .encrypt(entry.name(), &params, message)
            .unwrap();
        let plaintext = ALGO
            .cipher()
            .decrypt(entry.name(), &params, &ciphertext)
            .unwrap();
        assert_eq!(plaintext, message, "{}", entry.name());
    }
}

#[test]
fn input_fed_in_pieces_gives_what_it_gives_at_once() {
    let params = params(
        "000102030405060708090a0b0c0d0e0f",
        Some("101112131415161718191a1b1c1d1e1f"),
    );
    let message: Vec<u8> = (0..50).collect();
    let mut cipher = ALGO.cipher().get_by_name("AES/CBC/PKCS7PADDING").unwrap();
    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    let mut pieces = Vec::new();
    for chunk in message.chunks(7) {
        pieces.extend(cipher.update(chunk).unwrap());
    }
    pieces.extend(cipher.finalize().unwrap());
    let at_once = ALGO
        .cipher()
        .encrypt("AES/CBC/PKCS7PADDING", &params, &message)
        .unwrap();
    assert_eq!(pieces, at_once);
}

#[test]
fn a_finished_cipher_takes_the_next_message_under_the_same_params() {
    let params = params(
        "000102030405060708090a0b0c0d0e0f",
        Some("101112131415161718191a1b1c1d1e1f"),
    );
    let mut cipher = ALGO.cipher().get_by_name("AES/CBC/PKCS7PADDING").unwrap();
    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    let mut first = cipher.update(b"message").unwrap();
    first.extend(cipher.finalize().unwrap());
    let mut second = cipher.update(b"message").unwrap();
    second.extend(cipher.finalize().unwrap());
    assert_eq!(first, second);
}

#[test]
fn a_finished_gcm_encryption_takes_a_new_init() {
    let params = aead_params(
        "000102030405060708090a0b0c0d0e0f",
        "101112131415161718191a1b",
        16,
    );
    let mut cipher = ALGO.cipher().get_by_name("AES/GCM/NOPADDING").unwrap();
    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    cipher.update(b"message").unwrap();
    cipher.finalize().unwrap();
    let error = cipher.update(b"message").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotInitialized);
}

#[test]
fn a_cipher_used_before_init_says_so() {
    let mut cipher = ALGO.cipher().get_by_name("AES/CBC/PKCS7PADDING").unwrap();
    assert_eq!(
        cipher.update(&[0; 16]).unwrap_err().kind(),
        ErrorKind::NotInitialized
    );
}

#[test]
fn names_follow_bouncy_castle_and_come_back_canonical() {
    for (name, canonical) in [
        ("AES", "AES/ECB/PKCS7PADDING"),
        ("aes/cbc", "AES/CBC/PKCS7PADDING"),
        ("AES//NoPadding", "AES/ECB/NOPADDING"),
        ("AES/CTR", "AES/CTR/NOPADDING"),
        ("AES/SIC/NoPadding", "AES/CTR/NOPADDING"),
        ("AES/CBC/PKCS5Padding", "AES/CBC/PKCS7PADDING"),
        ("AES/CBC/ISO10126_2PADDING", "AES/CBC/ISO10126PADDING"),
        ("AES/GCM", "AES/GCM/NOPADDING"),
    ] {
        let cipher = ALGO.cipher().get_by_name(name).unwrap();
        assert_eq!(cipher.entry().name(), canonical, "{name}");
    }
}

#[test]
fn a_name_outside_the_table_is_an_unknown_cipher() {
    for name in [
        "",
        "NOSUCH",
        "AES/NOSUCH",
        "AES/CBC/NOSUCH",
        "AES/GCM/PKCS7PADDING",
        "AES/CBC/PKCS7PADDING/MORE",
    ] {
        let error = ALGO.cipher().get_by_name(name).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownCipher, "{name}");
    }
}

#[test]
fn every_oid_finds_the_combination_it_names() {
    let mut count = 0;
    for entry in aes_entries() {
        for oid in entry.oids() {
            let cipher = ALGO.cipher().get_by_oid(&oid.oid()).unwrap();
            assert_eq!(cipher.entry().name(), entry.name(), "{}", oid.dotted());
            count += 1;
        }
    }
    assert_eq!(count, 18);
    let found = ALGO
        .cipher()
        .get_by_oid(&ALGO.cipher().get_by_name("AES/CBC").unwrap().entry().oids()[2].oid())
        .unwrap();
    assert_eq!(found.entry().name(), "AES/CBC/PKCS7PADDING");
}

#[test]
fn ecb_refuses_an_iv() {
    let params = params(
        "000102030405060708090a0b0c0d0e0f",
        Some("101112131415161718191a1b1c1d1e1f"),
    );
    let mut cipher = ALGO.cipher().get_by_name("AES/ECB/PKCS7PADDING").unwrap();
    let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn cbc_refuses_to_run_without_an_iv() {
    let params = params("000102030405060708090a0b0c0d0e0f", None);
    let mut cipher = ALGO.cipher().get_by_name("AES/CBC/PKCS7PADDING").unwrap();
    let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn a_block_mode_refuses_the_fields_of_an_aead_mode() {
    let mut with_tag = params(
        "000102030405060708090a0b0c0d0e0f",
        Some("101112131415161718191a1b1c1d1e1f"),
    );
    with_tag.op.tag_len = Some(16);
    let mut with_aad = with_tag.clone();
    with_aad.op.tag_len = None;
    with_aad.op.aad = Some(b"header".to_vec());
    for params in [with_tag, with_aad] {
        let mut cipher = ALGO.cipher().get_by_name("AES/CBC/PKCS7PADDING").unwrap();
        let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[test]
fn an_aead_mode_refuses_to_run_without_a_tag_length() {
    let params = params(
        "000102030405060708090a0b0c0d0e0f",
        Some("101112131415161718191a1b"),
    );
    let mut cipher = ALGO.cipher().get_by_name("AES/GCM/NOPADDING").unwrap();
    let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn the_associated_data_is_authenticated() {
    let mut params = aead_params(
        "000102030405060708090a0b0c0d0e0f",
        "101112131415161718191a1b",
        16,
    );
    params.op.aad = Some(b"header".to_vec());
    let ciphertext = ALGO
        .cipher()
        .encrypt("AES/GCM/NOPADDING", &params, b"message")
        .unwrap();
    assert_eq!(
        ALGO.cipher()
            .decrypt("AES/GCM/NOPADDING", &params, &ciphertext)
            .unwrap(),
        b"message"
    );
    params.op.aad = Some(b"other".to_vec());
    let error = ALGO
        .cipher()
        .decrypt("AES/GCM/NOPADDING", &params, &ciphertext)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
}

#[test]
fn a_key_of_a_length_aes_does_not_have_is_invalid() {
    let params = params("0001020304", None);
    let mut cipher = ALGO.cipher().get_by_name("AES/ECB/PKCS7PADDING").unwrap();
    let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[cfg(feature = "x25519")]
#[test]
fn a_block_cipher_refuses_a_key_that_is_not_secret() {
    use tc_algo_old::AnyPrivateKey;
    let key = tc_cfrg_curves::X25519PrivateKey::new([7; 32]);
    let params = AnyParams::new(AnyKeyParams::Private(AnyPrivateKey::X25519(key)));
    let mut cipher = ALGO.cipher().get_by_name("AES/ECB/PKCS7PADDING").unwrap();
    let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn a_wrong_padding_and_a_wrong_tag_fail_alike() {
    let key = "000102030405060708090a0b0c0d0e0f";
    let cbc = params(key, Some("101112131415161718191a1b1c1d1e1f"));
    let mut ciphertext = ALGO
        .cipher()
        .encrypt("AES/CBC/PKCS7PADDING", &cbc, b"message")
        .unwrap();
    ciphertext[15] ^= 1;
    let padding = ALGO
        .cipher()
        .decrypt("AES/CBC/PKCS7PADDING", &cbc, &ciphertext)
        .unwrap_err();
    let gcm = aead_params(key, "101112131415161718191a1b", 16);
    let mut ciphertext = ALGO
        .cipher()
        .encrypt("AES/GCM/NOPADDING", &gcm, b"message")
        .unwrap();
    ciphertext[0] ^= 1;
    let tag = ALGO
        .cipher()
        .decrypt("AES/GCM/NOPADDING", &gcm, &ciphertext)
        .unwrap_err();
    assert_eq!(padding.kind(), ErrorKind::InvalidCiphertext);
    assert_eq!(tag.kind(), ErrorKind::InvalidCiphertext);
}

#[test]
fn the_table_has_every_mode_and_padding_but_aead_only_without_padding() {
    assert_eq!(aes_entries().count(), 5 * 7 + 4);
    let entry = ALGO.cipher().get_by_name("AES/CBC").unwrap();
    assert_eq!(
        entry.entry().to_string(),
        "AES/CBC/PKCS7PADDING  [id-aes128-CBC, id-aes192-CBC, id-aes256-CBC]"
    );
}

#[test]
fn debug_shows_the_name_but_not_the_key() {
    let mut cipher = ALGO.cipher().get_by_name("AES/ECB").unwrap();
    cipher
        .init(
            CipherDirection::Encrypt,
            &params("000102030405060708090a0b0c0d0e0f", None),
        )
        .unwrap();
    assert_eq!(
        format!("{cipher:?}"),
        "AnyCipher { name: \"AES/ECB/PKCS7PADDING\", .. }"
    );
    assert_eq!(cipher.to_string(), "AES/ECB/PKCS7PADDING");
}
