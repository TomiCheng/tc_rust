#![cfg(feature = "rsa")]

use std::sync::LazyLock;

use tc_algo::ErrorKind;
use tc_algo::cipher::{self, CipherDirection, CipherEntry};
use tc_algo::generate::{self, KeyGenParams, KeyPair};
use tc_algo::params::{AnyKeyParams, AnyParams, AnyPrivateKey, AnyPublicKey, SecretKey};
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit};
use tc_rsa::{RsaEngine, RsaKey};

// One key pair for every test: 1536 bits is the smallest round size that holds OAEP with SHA-512
static KEYS: LazyLock<KeyPair> = LazyLock::new(|| {
    let mut generator = generate::get_key_pair_generator("RSA").unwrap();
    generator
        .init(KeyGenParams::rsa().with_bits(1536).with_certainty(20))
        .unwrap();
    generator.generate().unwrap()
});

fn rsa_keys() -> (&'static RsaKey, &'static RsaKey) {
    let (AnyPublicKey::Rsa(public), AnyPrivateKey::Rsa(private)) = (&KEYS.public, &KEYS.private)
    else {
        panic!("not an RSA key pair");
    };
    (public, private)
}

fn public() -> AnyParams {
    AnyParams::new(AnyKeyParams::Public(KEYS.public.clone()))
}

fn private() -> AnyParams {
    AnyParams::new(AnyKeyParams::Private(KEYS.private.clone()))
}

fn rsa_entries() -> impl Iterator<Item = &'static CipherEntry> {
    cipher::algorithms().filter(|entry| entry.name().starts_with("RSA/"))
}

#[test]
fn every_padding_decrypts_with_the_private_key_what_the_public_key_encrypts() {
    for entry in rsa_entries() {
        let ciphertext = cipher::encrypt(entry.name(), &public(), b"attack at dawn").unwrap();
        assert_eq!(ciphertext.len(), 192, "{}", entry.name());
        let plaintext = cipher::decrypt(entry.name(), &private(), &ciphertext).unwrap();
        // Raw RSA gives the whole block back, the leading zeros included
        assert!(plaintext.ends_with(b"attack at dawn"), "{}", entry.name());
    }
}

#[test]
fn raw_rsa_gives_what_the_rsa_engine_gives() {
    let (public_key, _) = rsa_keys();
    let mut engine = RsaEngine::new();
    engine
        .init(tc_asym_cipher::CipherDirection::Encrypt, public_key)
        .unwrap();
    let mut expected = vec![0; engine.output_block_size()];
    engine
        .process_block(b"attack at dawn", &mut expected)
        .unwrap();
    let output = cipher::encrypt("RSA/NONE/NOPADDING", &public(), b"attack at dawn").unwrap();
    assert_eq!(output, expected);
}

#[test]
fn oaep_with_mgf1_over_sha_1_differs_from_oaep_over_sha_256_alone() {
    let name = "RSA/NONE/OAEPWITHSHA256ANDMGF1WITHSHA1PADDING";
    let ciphertext = cipher::encrypt(name, &public(), b"attack at dawn").unwrap();
    assert_eq!(
        cipher::decrypt(name, &private(), &ciphertext).unwrap(),
        b"attack at dawn"
    );
    let other = "RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING";
    let error = cipher::decrypt(other, &private(), &ciphertext).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
}

#[test]
fn pkcs1_encrypts_with_the_private_key_and_decrypts_with_the_public_one_as_bouncy_castle_does() {
    let ciphertext = cipher::encrypt("RSA/NONE/PKCS1PADDING", &private(), b"message").unwrap();
    let plaintext = cipher::decrypt("RSA/NONE/PKCS1PADDING", &public(), &ciphertext).unwrap();
    assert_eq!(plaintext, b"message");
}

#[test]
fn a_changed_ciphertext_fails_alike_under_pkcs1_and_oaep() {
    for name in [
        "RSA/NONE/PKCS1PADDING",
        "RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING",
    ] {
        let mut ciphertext = cipher::encrypt(name, &public(), b"message").unwrap();
        ciphertext[100] ^= 1;
        let error = cipher::decrypt(name, &private(), &ciphertext).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext, "{name}");
    }
}

#[test]
fn a_message_longer_than_the_padding_leaves_room_for_is_a_data_length_error() {
    // PKCS#1 v1.5 takes at most 192 - 11 bytes
    let error = cipher::encrypt("RSA/NONE/PKCS1PADDING", &public(), &[1; 182]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DataLength);
    assert!(cipher::encrypt("RSA/NONE/PKCS1PADDING", &public(), &[1; 181]).is_ok());
}

#[test]
fn names_follow_bouncy_castle_and_come_back_canonical() {
    for (name, canonical) in [
        ("RSA", "RSA/NONE/NOPADDING"),
        ("rsa/ecb/pkcs1padding", "RSA/NONE/PKCS1PADDING"),
        ("RSA//PKCS1", "RSA/NONE/PKCS1PADDING"),
        ("RSA//OAEPPADDING", "RSA/NONE/OAEPWITHSHA1ANDMGF1PADDING"),
        (
            "RSA/NONE/OAEPWithSHA-256AndMGF1Padding",
            "RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING",
        ),
        (
            "RSA/ECB/OAEPWITHSHA-256ANDMGF1WITHSHA-256PADDING",
            "RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING",
        ),
    ] {
        let cipher = cipher::get_by_name(name).unwrap();
        assert_eq!(cipher.entry().name(), canonical, "{name}");
    }
}

#[test]
fn a_mode_or_a_block_padding_is_an_unknown_cipher_for_rsa() {
    for name in [
        "RSA/CBC/PKCS1PADDING",
        "RSA/NONE/PKCS7PADDING",
        "RSA/NONE/NOSUCH",
    ] {
        let error = cipher::get_by_name(name).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownCipher, "{name}");
    }
}

#[test]
fn the_pkcs_1_oids_find_pkcs1_and_oaep_with_sha_1() {
    let mut found = Vec::new();
    for entry in rsa_entries() {
        for oid in entry.oids() {
            let cipher = cipher::get_by_oid(&oid.oid()).unwrap();
            assert_eq!(cipher.entry().name(), entry.name(), "{}", oid.dotted());
            found.push(format!("{} {}", oid.dotted(), entry.name()));
        }
    }
    found.sort();
    assert_eq!(
        found,
        [
            "1.2.840.113549.1.1.1 RSA/NONE/PKCS1PADDING",
            "1.2.840.113549.1.1.7 RSA/NONE/OAEPWITHSHA1ANDMGF1PADDING",
        ]
    );
}

#[test]
fn the_table_has_rsa_with_each_of_its_paddings() {
    let iso9796 = usize::from(cfg!(feature = "rsa-iso9796"));
    let md5 = usize::from(cfg!(feature = "md5"));
    assert_eq!(rsa_entries().count(), 8 + iso9796 + md5);
}

#[cfg(feature = "rsa-iso9796")]
#[test]
fn iso_9796_1_finds_its_names_and_refuses_a_changed_ciphertext() {
    for name in ["RSA//ISO9796-1", "rsa/ecb/iso9796-1padding"] {
        let cipher = cipher::get_by_name(name).unwrap();
        assert_eq!(cipher.entry().name(), "RSA/NONE/ISO9796-1PADDING", "{name}");
    }
    let name = "RSA/NONE/ISO9796-1PADDING";
    let mut ciphertext = cipher::encrypt(name, &public(), b"message").unwrap();
    ciphertext[100] ^= 1;
    let error = cipher::decrypt(name, &private(), &ciphertext).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
}

#[cfg(feature = "md5")]
#[test]
fn oaep_with_md5_comes_with_the_md5_feature() {
    let name = "RSA/NONE/OAEPWITHMD5ANDMGF1PADDING";
    let ciphertext = cipher::encrypt(name, &public(), b"attack at dawn").unwrap();
    assert_eq!(
        cipher::decrypt(name, &private(), &ciphertext).unwrap(),
        b"attack at dawn"
    );
}

#[test]
fn rsa_refuses_an_operation_field() {
    let mut with_iv = public();
    with_iv.op.iv = Some(vec![0; 16]);
    let mut with_tag = public();
    with_tag.op.tag_len = Some(16);
    let mut with_aad = public();
    with_aad.op.aad = Some(b"header".to_vec());
    for params in [with_iv, with_tag, with_aad] {
        let mut cipher = cipher::get_by_name("RSA/NONE/PKCS1PADDING").unwrap();
        let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[test]
fn rsa_refuses_a_secret_key() {
    let params = AnyParams::new(AnyKeyParams::Secret(SecretKey::new(vec![1; 16])));
    let mut cipher = cipher::get_by_name("RSA/NONE/PKCS1PADDING").unwrap();
    let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn a_key_in_the_wrong_variant_is_refused() {
    let (public_key, private_key) = rsa_keys();
    for key in [
        AnyKeyParams::Public(AnyPublicKey::Rsa(private_key.clone())),
        AnyKeyParams::Private(AnyPrivateKey::Rsa(public_key.clone())),
    ] {
        let mut cipher = cipher::get_by_name("RSA/NONE/PKCS1PADDING").unwrap();
        let error = cipher
            .init(CipherDirection::Encrypt, &AnyParams::new(key))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[cfg(feature = "aes")]
#[test]
fn a_block_cipher_refuses_an_rsa_key() {
    let mut cipher = cipher::get_by_name("AES/ECB").unwrap();
    let error = cipher
        .init(CipherDirection::Encrypt, &public())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
}

#[test]
fn the_entry_shows_its_name_and_oid() {
    let entry = cipher::get_by_name("RSA//PKCS1").unwrap().entry();
    assert_eq!(entry.to_string(), "RSA/NONE/PKCS1PADDING  [rsaEncryption]");
}
