// The AEAD ciphers of their own, not the AEAD modes of the block ciphers: a known answer for each
// from the tests of its crate, then what holds for all of them
#![cfg(any(
    feature = "chacha20-poly1305",
    feature = "xchacha20-poly1305",
    feature = "ascon-aead128",
    feature = "ascon-legacy",
    feature = "grain128-aead",
    feature = "sparkle"
))]

use std::sync::LazyLock;

use tc_algo_old::{Algo, AnyKeyParams, AnyParams, CipherDirection, ErrorKind, SecretKey};

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

fn params(key: &[u8], nonce: &[u8], tag_len: usize, aad: &[u8]) -> AnyParams {
    let mut params = AnyParams::new(AnyKeyParams::Secret(SecretKey::new(key.to_vec())));
    params.op.iv = Some(nonce.to_vec());
    params.op.tag_len = Some(tag_len);
    if !aad.is_empty() {
        params.op.aad = Some(aad.to_vec());
    }
    params
}

#[allow(dead_code, reason = "each known answer has its own feature")]
fn assert_sealed(name: &str, params: &AnyParams, plaintext: &[u8], sealed: &[u8]) {
    assert_eq!(
        ALGO.cipher().encrypt(name, params, plaintext).unwrap(),
        sealed,
        "{name}"
    );
    assert_eq!(
        ALGO.cipher().decrypt(name, params, sealed).unwrap(),
        plaintext,
        "{name}"
    );
}

#[allow(dead_code, reason = "used by the ChaCha known answers")]
const SUNSCREEN: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only \
    one tip for the future, sunscreen would be it.";

#[cfg(feature = "chacha20-poly1305")]
#[test]
fn chacha20_poly1305_gives_the_rfc_8439_ciphertext_and_tag() {
    let params = params(
        &hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        &hex("070000004041424344454647"),
        16,
        &hex("50515253c0c1c2c3c4c5c6c7"),
    );
    let sealed = hex(concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691",
    ));
    assert_sealed("CHACHA20-POLY1305", &params, SUNSCREEN, &sealed);
}

#[cfg(feature = "xchacha20-poly1305")]
#[test]
fn xchacha20_poly1305_gives_the_draft_ciphertext_and_tag() {
    let params = params(
        &hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        &hex("404142434445464748494a4b4c4d4e4f5051525354555657"),
        16,
        &hex("50515253c0c1c2c3c4c5c6c7"),
    );
    let sealed = hex(concat!(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
        "21f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49",
    ));
    assert_sealed("XCHACHA20-POLY1305", &params, SUNSCREEN, &sealed);
}

#[cfg(feature = "ascon-aead128")]
#[test]
fn ascon_aead128_gives_the_known_ciphertext_and_tag() {
    let params = params(
        &hex("000102030405060708090A0B0C0D0E0F"),
        &hex("101112131415161718191A1B1C1D1E1F"),
        16,
        &[],
    );
    assert_sealed(
        "ASCON-AEAD128",
        &params,
        &hex("2021222324252627"),
        &hex("E8C3DEEE246CC5EAE455EF6B33B782A3DD91ED6695373C27"),
    );
}

#[cfg(feature = "ascon-legacy")]
#[test]
fn ascon_128_gives_the_known_ciphertext_and_tag() {
    let params = params(
        &hex("000102030405060708090A0B0C0D0E0F"),
        &hex("000102030405060708090A0B0C0D0E0F"),
        16,
        &[],
    );
    assert_sealed(
        "ASCON-128",
        &params,
        &hex("0001020304050607"),
        &hex("BC820DBDF7A4631C01A8807A44254B42AC6BB490DA1E000A"),
    );
}

#[cfg(feature = "grain128-aead")]
#[test]
fn grain_128aead_gives_the_known_ciphertext_and_tag() {
    let params = params(
        &hex("000102030405060708090A0B0C0D0E0F"),
        &hex("000102030405060708090A0B"),
        8,
        &[],
    );
    assert_sealed(
        "GRAIN-128AEAD",
        &params,
        &hex("000102030405060708090A0B0C0D0E0F"),
        &hex("21678706FB8AB6369ED9B5AFA619F8B27DEA6B6B907BE8FF"),
    );
}

#[cfg(feature = "sparkle")]
#[test]
fn schwaemm128_128_gives_the_known_ciphertext_and_tag() {
    let params = params(
        &hex("000102030405060708090A0B0C0D0E0F"),
        &hex("000102030405060708090A0B0C0D0E0F"),
        16,
        &[],
    );
    assert_sealed(
        "SCHWAEMM128-128",
        &params,
        &hex("000102030405060708090A0B0C0D0E0F"),
        &hex("FEDAD36D1A592AEB931BA52BA4056865F5544DD3488406F6AADF8EDAAE271727"),
    );
}

// The key, nonce and tag lengths each takes
const SIZES: &[(&str, usize, usize, usize)] = &[
    ("CHACHA20-POLY1305", 32, 12, 16),
    ("XCHACHA20-POLY1305", 32, 24, 16),
    ("ASCON-AEAD128", 16, 16, 16),
    ("ASCON-128", 16, 16, 16),
    ("ASCON-128A", 16, 16, 16),
    ("ASCON-80PQ", 20, 16, 16),
    ("GRAIN-128AEAD", 16, 12, 8),
    ("SCHWAEMM128-128", 16, 16, 16),
    ("SCHWAEMM256-128", 16, 32, 16),
    ("SCHWAEMM192-192", 24, 24, 24),
    ("SCHWAEMM256-256", 32, 32, 32),
];

fn enabled() -> impl Iterator<Item = (&'static str, usize, usize, usize)> {
    SIZES.iter().copied().filter(|(name, ..)| {
        ALGO.cipher()
            .algorithms()
            .any(|entry| entry.name() == *name)
    })
}

#[test]
fn every_aead_cipher_decrypts_what_it_encrypts_and_refuses_a_change() {
    let message: Vec<u8> = (0..100).collect();
    for (name, key, nonce, tag) in enabled() {
        let params = params(&vec![1; key], &vec![2; nonce], tag, b"header");
        let mut sealed = ALGO.cipher().encrypt(name, &params, &message).unwrap();
        assert_eq!(sealed.len(), message.len() + tag, "{name}");
        assert_eq!(
            ALGO.cipher().decrypt(name, &params, &sealed).unwrap(),
            message,
            "{name}"
        );
        sealed[50] ^= 1;
        let error = ALGO.cipher().decrypt(name, &params, &sealed).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext, "{name}");
    }
}

#[test]
fn the_table_has_each_aead_cipher_of_the_enabled_features() {
    let mut listed: Vec<&str> = ALGO
        .cipher()
        .algorithms()
        .map(|entry| entry.name())
        .filter(|name| SIZES.iter().any(|(known, ..)| known == name))
        .collect();
    listed.sort_unstable();
    let mut expected: Vec<&str> = enabled().map(|(name, ..)| name).collect();
    expected.sort_unstable();
    assert_eq!(listed, expected);
}

#[test]
fn an_aead_cipher_needs_a_nonce_and_a_tag_length() {
    for (name, key, nonce, tag) in enabled() {
        let mut without_nonce = params(&vec![1; key], &vec![2; nonce], tag, &[]);
        without_nonce.op.iv = None;
        let mut without_tag = params(&vec![1; key], &vec![2; nonce], tag, &[]);
        without_tag.op.tag_len = None;
        for params in [without_nonce, without_tag] {
            let mut cipher = ALGO.cipher().get_by_name(name).unwrap();
            let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidParams, "{name}");
        }
    }
}

#[test]
fn an_aead_cipher_takes_neither_a_mode_nor_a_padding() {
    for (name, ..) in enabled() {
        for suffix in ["/NONE/NOPADDING", "/GCM", "/"] {
            let error = ALGO
                .cipher()
                .get_by_name(&format!("{name}{suffix}"))
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::UnknownCipher, "{name}{suffix}");
        }
    }
}

#[test]
fn encrypting_again_takes_a_new_nonce() {
    for (name, key, nonce, tag) in enabled() {
        let params = params(&vec![1; key], &vec![2; nonce], tag, &[]);
        let mut cipher = ALGO.cipher().get_by_name(name).unwrap();
        cipher.init(CipherDirection::Encrypt, &params).unwrap();
        cipher.update(b"message").unwrap();
        cipher.finalize().unwrap();
        let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams, "{name}");
        let next = params_with_nonce(&params, &vec![3; nonce]);
        cipher.init(CipherDirection::Encrypt, &next).unwrap();
    }
}

fn params_with_nonce(params: &AnyParams, nonce: &[u8]) -> AnyParams {
    let mut next = params.clone();
    next.op.iv = Some(nonce.to_vec());
    next
}

#[cfg(feature = "chacha20-poly1305")]
#[test]
fn chacha20_poly1305_follows_bouncy_castle_for_its_names_and_oid() {
    for name in ["ChaCha20-Poly1305", "chacha20_poly1305"] {
        let cipher = ALGO.cipher().get_by_name(name).unwrap();
        assert_eq!(cipher.entry().name(), "CHACHA20-POLY1305", "{name}");
    }
    let found = ALGO.cipher().get_by_name("CHACHA20-POLY1305").unwrap();
    let entry = found.entry();
    assert_eq!(
        entry.to_string(),
        "CHACHA20-POLY1305  [id-alg-AEADChaCha20Poly1305]"
    );
    let cipher = ALGO.cipher().get_by_oid(&entry.oids()[0].oid()).unwrap();
    assert_eq!(cipher.entry().name(), "CHACHA20-POLY1305");
}

#[cfg(feature = "chacha20-poly1305")]
#[test]
fn chacha20_poly1305_refuses_a_tag_other_than_sixteen_bytes() {
    let params = params(&[1; 32], &[2; 12], 12, &[]);
    let mut cipher = ALGO.cipher().get_by_name("CHACHA20-POLY1305").unwrap();
    let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}
