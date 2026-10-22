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

#[cfg(any(feature = "ed25519", feature = "ed448"))]
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[cfg(any(feature = "ed25519", feature = "ed448"))]
type KeyPair = (
    tc_security::params::AnyParams,
    tc_security::params::AnyParams,
);

// 由 RFC 的 bytes 建出（公鑰, 私鑰）
#[cfg(feature = "ed25519")]
fn ed25519_keys(private: &[u8], public: &[u8]) -> KeyPair {
    use tc_security::params::AnyParams;

    (
        AnyParams::Ed25519Public {
            key: tc_cfrg_curves::Ed25519PublicKey::new(public.try_into().unwrap()),
        },
        AnyParams::Ed25519Private {
            key: tc_cfrg_curves::Ed25519PrivateKey::new(private.try_into().unwrap()),
        },
    )
}

#[cfg(feature = "ed448")]
fn ed448_keys(private: &[u8], public: &[u8]) -> KeyPair {
    use tc_security::params::AnyParams;

    (
        AnyParams::Ed448Public {
            key: tc_cfrg_curves::Ed448PublicKey::new(public.try_into().unwrap()),
        },
        AnyParams::Ed448Private {
            key: tc_cfrg_curves::Ed448PrivateKey::new(private.try_into().unwrap()),
        },
    )
}

#[cfg(all(feature = "ed25519", feature = "ed448"))]
#[test]
fn ed_signers_are_found_by_bc_names_and_rfc_8410_oids() {
    for (name, expected) in [
        ("ed25519", "Ed25519"),
        ("1.3.101.112", "Ed25519"),
        ("ED25519CTX", "Ed25519ctx"),
        ("ed25519ph", "Ed25519ph"),
        ("ED448", "Ed448"),
        ("1.3.101.113", "Ed448"),
        ("ed448PH", "Ed448ph"),
    ] {
        assert_eq!(name_of(name), Ok(expected), "{name}");
    }
}

// RFC 8032 中 context 是空的向量；BC 的工廠一律用空的 context
#[cfg(any(feature = "ed25519", feature = "ed448"))]
#[test]
fn the_ed_signers_give_the_rfc_8032_signatures_with_an_empty_context() {
    type Keys = fn(&[u8], &[u8]) -> KeyPair;
    let vectors: &[(&str, Keys, &str, &str, &str, &str)] = &[
        #[cfg(feature = "ed25519")]
        (
            "Ed25519",
            ed25519_keys,
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        #[cfg(feature = "ed25519")]
        (
            "Ed25519ph",
            ed25519_keys,
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "616263",
            "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
        ),
        #[cfg(feature = "ed448")]
        (
            "Ed448",
            ed448_keys,
            "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
            "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
            "",
            "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600",
        ),
        #[cfg(feature = "ed448")]
        (
            "Ed448ph",
            ed448_keys,
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49",
            "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880",
            "616263",
            "822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00",
        ),
    ];
    for &(name, keys, private, public, message, expected) in vectors {
        let (public, private) = keys(&hex(private), &hex(public));
        let mut signer = signer::get_by_name(name).unwrap().signer();
        let signature = signer::sign(&mut signer, &private, &hex(message)).unwrap();
        assert_eq!(signature, hex(expected), "{name}");
        assert!(
            signer::verify(&mut signer, &public, &hex(message), &signature).unwrap(),
            "{name}"
        );
    }
}

// 產生器與簽章器用同一個名稱；ctx 與 ph 的簽章互不相通
#[cfg(any(feature = "ed25519", feature = "ed448"))]
#[test]
fn every_ed_signer_verifies_its_own_signature_from_generated_keys() {
    use tc_security::generate;

    for entry in signer::algorithms().filter(|entry| entry.name().starts_with("Ed")) {
        let name = entry.name();
        let mut generator = generate::get_by_name(name).unwrap().generator();
        let (public, private) = generator.generate_key_pair().unwrap();
        let (other_public, _) = generator.generate_key_pair().unwrap();

        let mut signer = entry.signer();
        let signature = signer::sign(&mut signer, &private, b"attack at dawn").unwrap();
        assert!(
            signer::verify(&mut signer, &public, b"attack at dawn", &signature).unwrap(),
            "{name}"
        );
        assert!(
            !signer::verify(&mut signer, &public, b"attack at dusk", &signature).unwrap(),
            "{name}"
        );
        assert!(
            !signer::verify(&mut signer, &other_public, b"attack at dawn", &signature).unwrap(),
            "{name}"
        );
        for other in signer::algorithms() {
            if other.name() == name || !other.name().starts_with(&name[..5]) {
                continue;
            }
            let mut other_signer = other.signer();
            assert!(
                !signer::verify(&mut other_signer, &public, b"attack at dawn", &signature).unwrap(),
                "{name} under {}",
                other.name()
            );
        }
    }
}

#[cfg(all(feature = "ed25519", feature = "ed448"))]
#[test]
fn an_ed_signer_rejects_keys_of_another_curve_or_side() {
    use tc_security::generate;
    use tc_signer::{Signer, SignerInit};

    let (public, private) = generate::get_by_name("Ed25519")
        .unwrap()
        .generator()
        .generate_key_pair()
        .unwrap();
    let (ed448_public, ed448_private) = generate::get_by_name("Ed448")
        .unwrap()
        .generator()
        .generate_key_pair()
        .unwrap();

    let mut signer = signer::get_by_name("Ed25519").unwrap().signer();
    for key in [&ed448_public, &ed448_private] {
        let error = signer.init(key).err().unwrap();
        assert_eq!(
            source::<SecurityError>(&error),
            Some(&SecurityError::WrongParams)
        );
    }

    // 公鑰不能簽、私鑰不能驗；底層的錯誤留在 source
    signer.init(&public).unwrap();
    let error = signer.generate_signature(&mut [0; 64]).err().unwrap();
    assert_eq!(
        source::<tc_cfrg_curves::CfrgError>(&error),
        Some(&tc_cfrg_curves::CfrgError::NotForSigning)
    );
    signer.init(&private).unwrap();
    let error = signer.verify_signature(&[0; 64]).err().unwrap();
    assert_eq!(
        source::<tc_cfrg_curves::CfrgError>(&error),
        Some(&tc_cfrg_curves::CfrgError::NotForVerifying)
    );
}
