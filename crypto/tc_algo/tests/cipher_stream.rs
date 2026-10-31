#![cfg(any(
    feature = "chacha",
    feature = "salsa20",
    feature = "rc4",
    feature = "vmpc",
    feature = "hc"
))]

use tc_algo::cipher::{self, CipherDirection};
use tc_algo::params::{AnyKeyParams, AnyParams, SecretKey};
use tc_stream_cipher::StreamCipher;

#[cfg(any(feature = "chacha", feature = "rc4"))]
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn params(key: &[u8], iv: Option<&[u8]>) -> AnyParams {
    let mut params = AnyParams::new(AnyKeyParams::Secret(SecretKey::new(key.to_vec())));
    params.op.iv = iv.map(<[u8]>::to_vec);
    params
}

fn run(engine: &mut impl StreamCipher, input: &[u8]) -> Vec<u8> {
    let mut output = vec![0; input.len()];
    engine.process_bytes(input, &mut output).unwrap();
    output
}

// Encrypts with the engine itself, from the key, the IV if any, and the input
type Engine = fn(&[u8], Option<&[u8]>, &[u8]) -> Vec<u8>;

// Each stream cipher of the enabled features: its name, a key and IV length it takes, and its
// engine
fn cases() -> Vec<(&'static str, usize, Option<usize>, Engine)> {
    #[allow(
        unused_imports,
        reason = "RC4 alone takes KeyRef, the others KeyWithIvRef"
    )]
    use tc_stream_cipher::{CipherDirection as Direction, KeyRef, KeyWithIvRef, StreamCipherInit};
    let mut cases: Vec<(&'static str, usize, Option<usize>, Engine)> = Vec::new();
    #[cfg(feature = "rc4")]
    cases.push(("ARC4", 16, None, |key, _, input| {
        let mut engine = tc_rc4_family::Rc4Engine::new();
        engine.init(Direction::Encrypt, &KeyRef::new(key)).unwrap();
        run(&mut engine, input)
    }));
    #[cfg(feature = "chacha")]
    cases.push(("CHACHA", 32, Some(8), |key, iv, input| {
        let mut engine = tc_chacha::ChaChaEngine::new();
        let params = KeyWithIvRef::new(key, iv.unwrap());
        engine.init(Direction::Encrypt, &params).unwrap();
        run(&mut engine, input)
    }));
    #[cfg(feature = "chacha")]
    cases.push(("CHACHA7539", 32, Some(12), |key, iv, input| {
        let mut engine = tc_chacha::ChaCha7539Engine::new();
        let params = KeyWithIvRef::new(key, iv.unwrap());
        engine.init(Direction::Encrypt, &params).unwrap();
        run(&mut engine, input)
    }));
    #[cfg(feature = "hc")]
    cases.push(("HC128", 16, Some(16), |key, iv, input| {
        let mut engine = tc_hc::Hc128Engine::new();
        let params = KeyWithIvRef::new(key, iv.unwrap());
        engine.init(Direction::Encrypt, &params).unwrap();
        run(&mut engine, input)
    }));
    #[cfg(feature = "hc")]
    cases.push(("HC256", 32, Some(32), |key, iv, input| {
        let mut engine = tc_hc::Hc256Engine::new();
        let params = KeyWithIvRef::new(key, iv.unwrap());
        engine.init(Direction::Encrypt, &params).unwrap();
        run(&mut engine, input)
    }));
    #[cfg(feature = "salsa20")]
    cases.push(("SALSA20", 32, Some(8), |key, iv, input| {
        let mut engine = tc_salsa20::Salsa20Engine::new();
        let params = KeyWithIvRef::new(key, iv.unwrap());
        engine.init(Direction::Encrypt, &params).unwrap();
        run(&mut engine, input)
    }));
    #[cfg(feature = "vmpc")]
    cases.push(("VMPC", 16, Some(16), |key, iv, input| {
        let mut engine = tc_rc4_family::VmpcEngine::new();
        let params = KeyWithIvRef::new(key, iv.unwrap());
        engine.init(Direction::Encrypt, &params).unwrap();
        run(&mut engine, input)
    }));
    #[cfg(feature = "vmpc")]
    cases.push(("VMPC-KSA3", 16, Some(16), |key, iv, input| {
        let mut engine = tc_rc4_family::VmpcKsa3Engine::new();
        let params = KeyWithIvRef::new(key, iv.unwrap());
        engine.init(Direction::Encrypt, &params).unwrap();
        run(&mut engine, input)
    }));
    #[cfg(feature = "chacha")]
    cases.push(("XCHACHA20", 32, Some(24), |key, iv, input| {
        let mut engine = tc_chacha::XChaCha20Engine::new();
        let params = KeyWithIvRef::new(key, iv.unwrap());
        engine.init(Direction::Encrypt, &params).unwrap();
        run(&mut engine, input)
    }));
    cases
}

fn case_params(key_len: usize, iv_len: Option<usize>) -> (Vec<u8>, Option<Vec<u8>>) {
    let key = (0..key_len).map(|i| i as u8).collect();
    let iv = iv_len.map(|len| (0..len).map(|i| 0x80 | i as u8).collect());
    (key, iv)
}

#[test]
fn each_stream_cipher_gives_what_its_engine_gives() {
    let message: Vec<u8> = (0..100).collect();
    for (name, key_len, iv_len, engine) in cases() {
        let (key, iv) = case_params(key_len, iv_len);
        let output = cipher::encrypt(name, &params(&key, iv.as_deref()), &message).unwrap();
        assert_eq!(output, engine(&key, iv.as_deref(), &message), "{name}");
    }
}

#[test]
fn each_stream_cipher_decrypts_what_it_encrypts_whatever_the_pieces() {
    let message: Vec<u8> = (0..200).map(|i| i as u8).collect();
    for (name, key_len, iv_len, _) in cases() {
        let (key, iv) = case_params(key_len, iv_len);
        let params = params(&key, iv.as_deref());
        let mut cipher = cipher::get_by_name(name).unwrap();
        cipher.init(CipherDirection::Encrypt, &params).unwrap();
        let mut ciphertext = Vec::new();
        for piece in [
            &message[..1],
            &message[1..8],
            &message[8..72],
            &message[72..],
        ] {
            let output = cipher.update(piece).unwrap();
            assert_eq!(output.len(), piece.len(), "{name}");
            ciphertext.extend(output);
        }
        assert!(cipher.finalize().unwrap().is_empty(), "{name}");
        assert_eq!(
            ciphertext,
            cipher::encrypt(name, &params, &message).unwrap(),
            "{name}"
        );
        assert_eq!(
            cipher::decrypt(name, &params, &ciphertext).unwrap(),
            message,
            "{name}"
        );
    }
}

#[test]
fn the_table_has_each_stream_cipher_of_the_enabled_features() {
    let mut listed: Vec<&str> = cipher::algorithms()
        .map(|entry| entry.name())
        .filter(|name| !name.contains('/'))
        .collect();
    listed.sort_unstable();
    let mut expected: Vec<&str> = cases().into_iter().map(|case| case.0).collect();
    expected.sort_unstable();
    assert_eq!(listed, expected);
}

#[test]
fn names_follow_bouncy_castle_and_come_back_canonical() {
    let mut names: Vec<(&str, &str)> = Vec::new();
    #[cfg(feature = "rc4")]
    names.extend([("rc4", "ARC4"), ("ARCFOUR", "ARC4"), ("arc4", "ARC4")]);
    #[cfg(feature = "chacha")]
    names.extend([
        ("chacha", "CHACHA"),
        ("ChaCha20", "CHACHA7539"),
        ("xchacha20", "XCHACHA20"),
    ]);
    #[cfg(feature = "salsa20")]
    names.push(("Salsa20", "SALSA20"));
    #[cfg(feature = "vmpc")]
    names.extend([("vmpc", "VMPC"), ("VMPC_KSA3", "VMPC-KSA3")]);
    #[cfg(feature = "hc")]
    names.extend([("hc128", "HC128"), ("hc256", "HC256")]);
    for (name, canonical) in names {
        let cipher = cipher::get_by_name(name).unwrap();
        assert_eq!(cipher.entry().name(), canonical, "{name}");
    }
}

#[cfg(feature = "chacha")]
mod with_chacha {
    use tc_algo::ErrorKind;
    use tc_algo::cipher::{self, CipherDirection};
    #[cfg(feature = "x25519")]
    use tc_algo::params::{AnyKeyParams, AnyParams};

    use super::{hex, params};

    #[test]
    fn chacha_and_chacha7539_give_the_rfc_8439_block_for_a_zero_key_and_iv() {
        let expected = hex(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
             da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
        );
        for (name, iv_len) in [("CHACHA", 8), ("CHACHA7539", 12)] {
            let params = params(&[0; 32], Some(&vec![0; iv_len]));
            let keystream = cipher::encrypt(name, &params, &[0; 64]).unwrap();
            assert_eq!(keystream, expected, "{name}");
        }
    }

    #[test]
    fn a_mode_or_a_padding_is_an_unknown_cipher_for_a_stream_cipher() {
        for name in [
            "CHACHA7539/NONE/NOPADDING",
            "CHACHA7539/ECB",
            "CHACHA7539/",
            "CHACHA7539//",
        ] {
            let error = cipher::get_by_name(name).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::UnknownCipher, "{name}");
        }
    }

    #[test]
    fn a_stream_cipher_with_an_iv_refuses_to_go_without_one() {
        let mut cipher = cipher::get_by_name("CHACHA7539").unwrap();
        let error = cipher
            .init(CipherDirection::Encrypt, &params(&[1; 32], None))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn a_stream_cipher_refuses_a_tag_length_and_associated_data() {
        let mut with_tag = params(&[1; 32], Some(&[2; 12]));
        with_tag.op.tag_len = Some(16);
        let mut with_aad = params(&[1; 32], Some(&[2; 12]));
        with_aad.op.aad = Some(b"header".to_vec());
        for params in [with_tag, with_aad] {
            let mut cipher = cipher::get_by_name("CHACHA7539").unwrap();
            let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidParams);
        }
    }

    #[test]
    fn a_key_or_iv_of_a_length_the_cipher_does_not_take_is_invalid_params() {
        for (key, iv) in [(16, 12), (32, 8)] {
            let mut cipher = cipher::get_by_name("CHACHA7539").unwrap();
            let error = cipher
                .init(
                    CipherDirection::Encrypt,
                    &params(&vec![1; key], Some(&vec![2; iv])),
                )
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidParams, "{key} {iv}");
        }
    }

    #[test]
    fn a_stream_cipher_before_init_is_not_initialized() {
        let mut cipher = cipher::get_by_name("CHACHA7539").unwrap();
        let error = cipher.update(b"message").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn finalize_starts_the_keystream_over_as_in_bouncy_castle() {
        let mut cipher = cipher::get_by_name("CHACHA7539").unwrap();
        cipher
            .init(CipherDirection::Encrypt, &params(&[1; 32], Some(&[2; 12])))
            .unwrap();
        let first = cipher.update(b"message").unwrap();
        assert!(cipher.finalize().unwrap().is_empty());
        assert_eq!(cipher.update(b"message").unwrap(), first);
    }

    #[cfg(feature = "x25519")]
    #[test]
    fn a_stream_cipher_refuses_a_key_that_is_not_secret() {
        use tc_algo::params::AnyPrivateKey;
        let key = tc_cfrg_curves::X25519PrivateKey::new([7; 32]);
        let mut params = AnyParams::new(AnyKeyParams::Private(AnyPrivateKey::X25519(key)));
        params.op.iv = Some(vec![2; 12]);
        let mut cipher = cipher::get_by_name("CHACHA7539").unwrap();
        let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[cfg(feature = "rc4")]
mod with_rc4 {
    use tc_algo::ErrorKind;
    use tc_algo::cipher::{self, CipherDirection};

    use super::{hex, params};

    #[test]
    fn arc4_gives_the_well_known_rc4_outputs() {
        for (key, plaintext, ciphertext) in [
            ("Key", "Plaintext", "bbf316e8d940af0ad3"),
            ("Wiki", "pedia", "1021bf0420"),
            ("Secret", "Attack at dawn", "45a01f645fc35b383552544b9bf5"),
        ] {
            let params = params(key.as_bytes(), None);
            let output = cipher::encrypt("ARC4", &params, plaintext.as_bytes()).unwrap();
            assert_eq!(output, hex(ciphertext), "{key}");
        }
    }

    #[test]
    fn the_rc4_oid_finds_arc4() {
        let entry = cipher::get_by_name("ARC4").unwrap().entry();
        assert_eq!(entry.to_string(), "ARC4  [rc4]");
        let cipher = cipher::get_by_oid(&entry.oids()[0].oid()).unwrap();
        assert_eq!(cipher.entry().name(), "ARC4");
    }

    #[test]
    fn rc4_refuses_an_iv() {
        let mut cipher = cipher::get_by_name("ARC4").unwrap();
        let error = cipher
            .init(CipherDirection::Encrypt, &params(&[1; 16], Some(&[2; 16])))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
