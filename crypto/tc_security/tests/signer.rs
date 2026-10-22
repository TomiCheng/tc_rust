//! 簽章器的查詢與使用：名稱與 OID 找到對應的一列，金鑰種類不對時拒絕。

use std::collections::HashSet;
use std::error::Error;

use tc_security::{AnyError, SecurityError, signer};

fn name_of(name: &str) -> Result<&'static str, SecurityError> {
    signer::get_by_name(name).map(|entry| entry.name())
}

#[allow(dead_code, reason = "signer 的 feature 都關掉時沒用到")]
fn source<E: Error + 'static>(error: &AnyError) -> Option<&E> {
    error.source()?.downcast_ref()
}

#[test]
fn every_entry_name_and_oid_is_unique() {
    let mut names = HashSet::new();
    let mut oids = HashSet::new();
    for entry in signer::algorithms() {
        assert!(names.insert(entry.name()), "{}", entry.name());
        for oid in entry.oids() {
            assert!(oids.insert(oid.dotted()), "{}", oid.dotted());
        }
    }
}

#[test]
fn an_unknown_name_or_oid_is_rejected() {
    assert_eq!(name_of("SHA-999withRSA"), Err(SecurityError::UnknownSigner));
    assert_eq!(name_of(""), Err(SecurityError::UnknownSigner));
    assert_eq!(name_of("1.2.3.4"), Err(SecurityError::UnknownSigner));
}

#[cfg(all(feature = "rsa", feature = "sha256", feature = "sha512-256"))]
#[test]
fn rsa_signers_are_found_by_bc_names_aliases_and_pkcs1_oids() {
    for (name, expected) in [
        ("sha-256withrsa", "SHA-256withRSA"),
        ("SHA256WITHRSA", "SHA-256withRSA"),
        ("SHA256withRSAEncryption", "SHA-256withRSA"),
        ("SHA-256WITHRSAENCRYPTION", "SHA-256withRSA"),
        ("1.2.840.113549.1.1.11", "SHA-256withRSA"),
        ("SHA512(256)withRSA", "SHA-512(256)withRSA"),
        ("1.2.840.113549.1.1.16", "SHA-512(256)withRSA"),
    ] {
        assert_eq!(name_of(name), Ok(expected), "{name}");
    }
}

#[cfg(feature = "rsa")]
fn rsa_pair() -> (
    tc_security::params::AnyParams,
    tc_security::params::AnyParams,
) {
    use tc_security::generate::{self, KeyGenParams};

    let mut generator = generate::get_by_name("RSA").unwrap().generator();
    generator
        .init(&KeyGenParams::Basic { strength: 1024 })
        .unwrap();
    generator.generate_key_pair().unwrap()
}

#[cfg(feature = "rsa")]
#[test]
fn every_rsa_signer_verifies_its_own_signature_and_nothing_else() {
    let (public, private) = rsa_pair();
    let (other_public, _) = rsa_pair();
    for entry in signer::algorithms().filter(|entry| entry.name().ends_with("withRSA")) {
        let name = entry.name();
        let mut rsa = entry.signer();
        let signature = signer::sign(&mut rsa, &private, b"attack at dawn").unwrap();
        assert_eq!(signature.len(), 128, "{name}");
        // PKCS#1 v1.5 是決定性的
        assert_eq!(
            signer::sign(&mut rsa, &private, b"attack at dawn").unwrap(),
            signature,
            "{name}"
        );

        assert!(
            signer::verify(&mut rsa, &public, b"attack at dawn", &signature).unwrap(),
            "{name}"
        );
        assert!(
            !signer::verify(&mut rsa, &public, b"attack at dusk", &signature).unwrap(),
            "{name}"
        );
        assert!(
            !signer::verify(&mut rsa, &other_public, b"attack at dawn", &signature).unwrap(),
            "{name}"
        );
        let mut bad = signature.clone();
        bad[0] ^= 1;
        assert!(
            !signer::verify(&mut rsa, &public, b"attack at dawn", &bad).unwrap(),
            "{name}"
        );
    }
}

#[cfg(all(feature = "rsa", feature = "sha256", feature = "sha384"))]
#[test]
fn an_rsa_signature_names_its_digest() {
    let (public, private) = rsa_pair();
    let mut sha256 = signer::get_by_name("SHA-256withRSA").unwrap().signer();
    let mut sha384 = signer::get_by_name("SHA-384withRSA").unwrap().signer();
    let signature = signer::sign(&mut sha256, &private, b"message").unwrap();
    assert!(!signer::verify(&mut sha384, &public, b"message", &signature).unwrap());
}

#[cfg(all(feature = "rsa", feature = "sha256"))]
#[test]
fn an_rsa_signer_rejects_the_wrong_key_for_each_side() {
    use tc_security::params::AnyParams;
    use tc_signer::{Signer, SignerInit};

    let (public, private) = rsa_pair();
    let mut rsa = signer::get_by_name("SHA-256withRSA").unwrap().signer();

    let error = signer::sign(&mut rsa, &AnyParams::new(vec![7; 16]), b"message")
        .err()
        .unwrap();
    assert_eq!(
        source::<SecurityError>(&error),
        Some(&SecurityError::WrongParams)
    );

    // 公鑰不能簽、私鑰不能驗；底層的錯誤留在 source
    rsa.init(&public).unwrap();
    let error = rsa.generate_signature(&mut [0; 128]).err().unwrap();
    assert_eq!(
        error.source().unwrap().to_string(),
        "signing requires a private key"
    );
    rsa.init(&private).unwrap();
    let error = rsa.verify_signature(&[0; 128]).err().unwrap();
    assert_eq!(
        error.source().unwrap().to_string(),
        "verification requires a public key"
    );
}
