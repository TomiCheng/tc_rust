//! key agreement 的查詢與計算：名稱與 OID 找到對應的一列，金鑰種類不對時拒絕。

use std::collections::HashSet;
use std::error::Error;

use tc_security::{AnyError, SecurityError, agreement, generate};

fn name_of(name: &str) -> Result<&'static str, SecurityError> {
    agreement::get_by_name(name).map(|entry| entry.name())
}

#[allow(dead_code, reason = "agreement 的 feature 都關掉時沒用到")]
fn source<E: Error + 'static>(error: &AnyError) -> Option<&E> {
    error.source()?.downcast_ref()
}

#[allow(dead_code, reason = "agreement 的 feature 都關掉時沒用到")]
fn hex<const N: usize>(text: &str) -> [u8; N] {
    core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}

#[test]
fn every_entry_name_and_oid_is_unique() {
    let mut names = HashSet::new();
    let mut oids = HashSet::new();
    for entry in agreement::algorithms() {
        assert!(names.insert(entry.name()), "{}", entry.name());
        for oid in entry.oids() {
            assert!(oids.insert(oid.dotted()), "{}", oid.dotted());
        }
    }
}

#[test]
fn an_unknown_name_or_oid_is_rejected() {
    assert_eq!(name_of("X9999"), Err(SecurityError::UnknownAgreement));
    assert_eq!(name_of(""), Err(SecurityError::UnknownAgreement));
    assert_eq!(name_of("1.2.3.4"), Err(SecurityError::UnknownAgreement));
}

#[cfg(all(feature = "x25519", feature = "x448"))]
#[test]
fn x25519_and_x448_are_found_by_name_and_rfc_8410_oid() {
    for (name, expected) in [
        ("x25519", "X25519"),
        ("1.3.101.110", "X25519"),
        ("x448", "X448"),
        ("1.3.101.111", "X448"),
    ] {
        assert_eq!(name_of(name), Ok(expected), "{name}");
    }
}

// RFC 7748 §6.1，經過工廠與 AnyParams
#[cfg(feature = "x25519")]
#[test]
fn x25519_reaches_the_rfc_7748_shared_secret() {
    use tc_cfrg_curves::{X25519PrivateKey, X25519PublicKey};
    use tc_security::params::AnyParams;

    let alice = AnyParams::X25519Private {
        key: X25519PrivateKey::new(hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        )),
    };
    let bob_public = AnyParams::X25519Public {
        key: X25519PublicKey::new(hex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        )),
    };
    let mut agreement = agreement::get_by_name("X25519").unwrap().agreement();
    assert_eq!(
        agreement::calculate_agreement(&mut agreement, &alice, &bob_public).unwrap(),
        hex::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    );
}

// RFC 7748 §6.2，經過工廠與 AnyParams
#[cfg(feature = "x448")]
#[test]
fn x448_reaches_the_rfc_7748_shared_secret() {
    use tc_cfrg_curves::{X448PrivateKey, X448PublicKey};
    use tc_security::params::AnyParams;

    let alice = AnyParams::X448Private {
        key: X448PrivateKey::new(hex(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        )),
    };
    let bob_public = AnyParams::X448Public {
        key: X448PublicKey::new(hex(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        )),
    };
    let mut agreement = agreement::get_by_name("X448").unwrap().agreement();
    assert_eq!(
        agreement::calculate_agreement(&mut agreement, &alice, &bob_public).unwrap(),
        hex::<56>(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
        )
    );
}

// 產生器與 agreement 用同一個名稱
#[test]
fn both_sides_of_every_agreement_reach_the_same_secret_from_generated_keys() {
    use tc_agreement::Agreement;

    for entry in agreement::algorithms() {
        let name = entry.name();
        let mut generator = generate::get_by_name(name).unwrap().generator();
        let (alice_public, alice_private) = generator.generate_key_pair().unwrap();
        let (bob_public, bob_private) = generator.generate_key_pair().unwrap();

        let mut agreement = entry.agreement();
        let alice =
            agreement::calculate_agreement(&mut agreement, &alice_private, &bob_public).unwrap();
        let bob =
            agreement::calculate_agreement(&mut agreement, &bob_private, &alice_public).unwrap();
        assert_eq!(alice.len(), agreement.agreement_size(), "{name}");
        assert_eq!(alice, bob, "{name}");
    }
}

#[cfg(all(feature = "x25519", feature = "x448"))]
#[test]
fn an_agreement_rejects_keys_of_another_kind() {
    use tc_security::params::AnyParams;

    let pair = |name| {
        let mut generator = generate::get_by_name(name).unwrap().generator();
        generator.generate_key_pair().unwrap()
    };
    let (public, private) = pair("X25519");
    let (x448_public, x448_private) = pair("X448");
    let symmetric = AnyParams::new(vec![7; 32]);

    let mut agreement = agreement::get_by_name("X25519").unwrap().agreement();
    for (private_key, public_key) in [
        (&symmetric, &public),
        (&public, &public),
        (&x448_private, &public),
        (&private, &private),
        (&private, &symmetric),
        (&private, &x448_public),
    ] {
        let error = agreement::calculate_agreement(&mut agreement, private_key, public_key)
            .err()
            .unwrap();
        assert_eq!(
            source::<SecurityError>(&error),
            Some(&SecurityError::WrongParams)
        );
    }
}

#[cfg(feature = "x25519")]
#[test]
fn the_underlying_failure_is_kept_as_the_source() {
    use tc_agreement::Agreement;
    use tc_cfrg_curves::{CfrgError, X25519PublicKey};
    use tc_security::params::AnyParams;

    let mut generator = generate::get_by_name("X25519").unwrap().generator();
    let (public, private) = generator.generate_key_pair().unwrap();
    let mut agreement = agreement::get_by_name("X25519").unwrap().agreement();

    let error = agreement
        .calculate_agreement(&public, &mut [0; 32])
        .err()
        .unwrap();
    assert_eq!(
        source::<CfrgError>(&error),
        Some(&CfrgError::NotInitialized)
    );

    // 小階點讓共享秘密全為零
    let zero = AnyParams::X25519Public {
        key: X25519PublicKey::new([0; 32]),
    };
    let error = agreement::calculate_agreement(&mut agreement, &private, &zero)
        .err()
        .unwrap();
    assert_eq!(
        source::<CfrgError>(&error),
        Some(&CfrgError::AgreementFailed)
    );
}
