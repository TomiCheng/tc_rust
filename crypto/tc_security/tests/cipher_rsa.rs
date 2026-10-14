#![cfg(feature = "rsa")]

use std::sync::OnceLock;

use tc_security::cipher::{self, Algorithm, Mode, Padding};
use tc_security::generate::{self, KeyGenParams};
use tc_security::params::{self, AnyParams};
use tc_security::{AnyError, SecurityError};

fn keys() -> &'static (AnyParams, AnyParams) {
    static KEYS: OnceLock<(AnyParams, AnyParams)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut generator = generate::get_by_name("RSA").unwrap().generator();
        generator
            .init(&KeyGenParams::Basic { strength: 1024 })
            .unwrap();
        generator.generate_key_pair().unwrap()
    })
}

fn name_of(name: &str) -> Result<String, SecurityError> {
    cipher::get_by_name(name).map(|entry| entry.name().to_string())
}

#[test]
fn rsa_names_follow_bc_with_an_empty_mode() {
    assert_eq!(name_of("RSA"), Ok("RSA//NOPADDING".into()));
    assert_eq!(
        name_of("RSA/ECB/PKCS1Padding"),
        Ok("RSA//PKCS1PADDING".into())
    );
    assert_eq!(name_of("rsa/none/pkcs1"), Ok("RSA//PKCS1PADDING".into()));
    assert_eq!(name_of("RSA//PKCS1PADDING"), Ok("RSA//PKCS1PADDING".into()));
    assert_eq!(
        name_of("1.2.840.113549.1.1.1"),
        Ok("RSA//PKCS1PADDING".into())
    );
    assert_eq!(
        cipher::get(Algorithm::Rsa, Some(Mode::Ecb), Some(Padding::Pkcs1))
            .map(|entry| entry.name()),
        Ok("RSA//PKCS1PADDING")
    );
    for name in [
        "RSA/CBC/PKCS1PADDING",
        "RSA//PKCS7PADDING",
        "AES/ECB/PKCS1PADDING",
    ] {
        assert_eq!(name_of(name), Err(SecurityError::UnknownCipher), "{name}");
    }
    assert_eq!(
        cipher::get(Algorithm::Rsa, Some(Mode::Cbc), None).err(),
        Some(SecurityError::UnknownCipher)
    );
}

#[cfg(feature = "sha256")]
#[test]
fn oaep_names_accept_bc_spellings() {
    for name in [
        "RSA/NONE/OAEPWithSHA-256AndMGF1Padding",
        "RSA//OAEPWITHSHA256ANDMGF1PADDING",
        "RSA/ECB/OAEPWithSHA256AndMGF1WithSHA256Padding",
    ] {
        assert_eq!(
            name_of(name),
            Ok("RSA//OAEPWITHSHA256ANDMGF1PADDING".into()),
            "{name}"
        );
    }
}

#[cfg(feature = "sha1")]
#[test]
fn plain_oaep_and_its_oid_are_oaep_with_sha1() {
    for name in ["RSA//OAEP", "RSA/NONE/OAEPPADDING", "1.2.840.113549.1.1.7"] {
        assert_eq!(
            name_of(name),
            Ok("RSA//OAEPWITHSHA1ANDMGF1PADDING".into()),
            "{name}"
        );
    }
}

#[test]
fn every_rsa_padding_encrypts_with_one_key_and_decrypts_with_the_other() {
    let (public, private) = keys();
    let message = b"attack at dawn";
    let rsa_entries = cipher::algorithms().filter(|entry| entry.algo() == Algorithm::Rsa);
    for entry in rsa_entries {
        // ISO 9796-1 is a signature format: the private key encodes and the public key recovers.
        #[cfg(feature = "iso9796")]
        let (encrypt_key, decrypt_key) = if entry.padding() == Some(Padding::Iso9796_1) {
            (private, public)
        } else {
            (public, private)
        };
        #[cfg(not(feature = "iso9796"))]
        let (encrypt_key, decrypt_key) = (public, private);

        let mut rsa = entry.cipher();
        // OAEP with SHA-512 needs 2 * 64 + 2 bytes of padding, more than a 1024-bit modulus holds.
        #[cfg(feature = "sha512")]
        if entry.padding() == Some(Padding::OaepSha512) {
            assert!(cipher::encrypt(&mut rsa, encrypt_key, message).is_err());
            continue;
        }
        let sealed = cipher::encrypt(&mut rsa, encrypt_key, message).unwrap();
        assert_eq!(sealed.len(), 128, "{entry}");
        let opened = cipher::decrypt(&mut rsa, decrypt_key, &sealed).unwrap();
        if entry.padding() == Some(Padding::NoPadding) {
            assert!(opened.ends_with(message), "{entry}");
            assert!(
                opened[..opened.len() - message.len()]
                    .iter()
                    .all(|&b| b == 0)
            );
        } else {
            assert_eq!(opened, message, "{entry}");
        }
    }
}

#[test]
fn pkcs1_pads_afresh_on_each_encryption() {
    let (public, _) = keys();
    let mut rsa = cipher::get_by_name("RSA//PKCS1PADDING").unwrap().cipher();
    let first = cipher::encrypt(&mut rsa, public, b"attack at dawn").unwrap();
    let second = cipher::encrypt(&mut rsa, public, b"attack at dawn").unwrap();
    assert_ne!(first, second);
}

#[test]
fn an_rsa_cipher_rejects_parameters_that_are_not_an_rsa_key() {
    let mut rsa = cipher::get_by_name("RSA//PKCS1PADDING").unwrap().cipher();
    let error: AnyError = cipher::encrypt(&mut rsa, &AnyParams::new(vec![7; 16]), b"x")
        .err()
        .unwrap();
    let mut source = std::error::Error::source(&error);
    let mut found = false;
    while let Some(error) = source {
        if error.downcast_ref::<SecurityError>() == Some(&SecurityError::WrongParams) {
            found = true;
        }
        source = error.source();
    }
    assert!(found);
}

#[test]
fn rsa_parameters_pass_the_key_on() {
    let (public, _) = keys();
    let params = params::get_by_name("RSA//PKCS1PADDING")
        .unwrap()
        .generator(public.clone())
        .generate()
        .unwrap();
    assert!(matches!(params, AnyParams::Rsa { .. }));
}
