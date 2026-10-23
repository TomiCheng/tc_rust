//! cipher 工廠的 ECIES：BC ECIESTest 的向量、雙方加解密、竄改與參數錯誤。

#![cfg(feature = "ecies")]

use std::error::Error;

use tc_ies::IesError;
use tc_security::cipher::{self, Algorithm};
use tc_security::generate::{self, KeyGenParams};
use tc_security::params::{AnyParams, EcCurve};
use tc_security::{AnyError, SecurityError};

const D: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const E: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];

#[cfg(feature = "ec-small-curves")]
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// 沿著 source 往下找第一個 `E`：工廠的 cipher 會再包一層 `AnyError`。
fn source<E: Error + 'static>(error: &AnyError) -> Option<&E> {
    let mut source = error.source();
    while let Some(error) = source {
        if let Some(found) = error.downcast_ref() {
            return Some(found);
        }
        source = error.source();
    }
    None
}

/// （公鑰, 私鑰），同產生器的順序。
fn ec_pair(curve: EcCurve) -> (AnyParams, AnyParams) {
    let mut generator = generate::get_by_name("ECIES").unwrap().generator();
    generator.init(&KeyGenParams::Ec { curve }).unwrap();
    generator.generate_key_pair().unwrap()
}

fn ies(private_key: &AnyParams, public_key: &AnyParams) -> AnyParams {
    AnyParams::ies(
        private_key.clone(),
        public_key.clone(),
        D.to_vec(),
        E.to_vec(),
        64,
    )
}

#[test]
fn ecies_is_a_standalone_cipher_found_by_bcs_name() {
    let entry = cipher::get_by_name("ecies").unwrap();
    assert_eq!(entry.algo(), Algorithm::Ecies);
    assert_eq!(entry.name(), "ECIES");
    assert!(cipher::get_by_name("ECIES/ECB/NOPADDING").is_err());
}

#[test]
fn what_alice_seals_for_bob_only_bob_opens() {
    let (alice_public, alice_private) = ec_pair(EcCurve::Secp256r1);
    let (bob_public, bob_private) = ec_pair(EcCurve::Secp256r1);
    let (_, eve_private) = ec_pair(EcCurve::Secp256r1);
    let message = b"attack at dawn";

    let mut ecies = cipher::get_by_name("ECIES").unwrap().cipher();
    let sealed = cipher::encrypt(&mut ecies, &ies(&alice_private, &bob_public), message).unwrap();
    assert_eq!(sealed.len(), message.len() + 20);
    assert_eq!(
        cipher::decrypt(&mut ecies, &ies(&bob_private, &alice_public), &sealed).unwrap(),
        message
    );

    let error =
        cipher::decrypt(&mut ecies, &ies(&eve_private, &alice_public), &sealed).unwrap_err();
    assert!(matches!(
        source::<IesError>(&error),
        Some(IesError::InvalidMac)
    ));
}

#[test]
fn a_changed_byte_fails_the_mac() {
    let (alice_public, alice_private) = ec_pair(EcCurve::Secp384r1);
    let (bob_public, bob_private) = ec_pair(EcCurve::Secp384r1);
    let mut ecies = cipher::get_by_name("ECIES").unwrap().cipher();
    let mut sealed =
        cipher::encrypt(&mut ecies, &ies(&alice_private, &bob_public), b"message").unwrap();
    sealed[3] ^= 1;
    let error =
        cipher::decrypt(&mut ecies, &ies(&bob_private, &alice_public), &sealed).unwrap_err();
    assert!(matches!(
        source::<IesError>(&error),
        Some(IesError::InvalidMac)
    ));
}

#[test]
fn ecies_takes_only_ies_parameters_with_ec_keys() {
    let (public, private) = ec_pair(EcCurve::Secp256r1);
    let (other_public, _) = ec_pair(EcCurve::Secp384r1);
    let mut ecies = cipher::get_by_name("ECIES").unwrap().cipher();

    let error = cipher::encrypt(&mut ecies, &AnyParams::new(vec![7; 32]), b"m").unwrap_err();
    assert_eq!(
        source::<SecurityError>(&error),
        Some(&SecurityError::WrongParams)
    );
    // 公鑰在另一條曲線上：agreement 拒絕
    let error = cipher::encrypt(&mut ecies, &ies(&private, &other_public), b"m").unwrap_err();
    assert!(matches!(
        source::<IesError>(&error),
        Some(IesError::Agreement(_))
    ));
    // 公私鑰放反
    let error = cipher::encrypt(&mut ecies, &ies(&public, &private), b"m").unwrap_err();
    assert!(matches!(
        source::<IesError>(&error),
        Some(IesError::Agreement(_))
    ));
}

// BC 的 ECIESTest：secp192r1 上的靜態金鑰 d 與 Q，雙方用同一組
#[cfg(feature = "ec-small-curves")]
#[test]
fn ecies_matches_bcs_ecies_vector() {
    use tc_bigint::{ArrayEncoding, PaddedBigUint};
    use tc_ec_key::{EcPrivateKey, EcPublicKey};
    use tc_fp_custom::named_curves::SECP192R1;
    use tc_security::params::{AnyEcPrivateKey, AnyEcPublicKey};

    let curve = Box::leak(Box::new(SECP192R1.ct_curve()));
    let g = SECP192R1.ct_generator(curve);
    let d = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&hex(
        "1a8d598fc15bf0fd89030b5cb1111aeb92ae8baf5ea475fb",
    ))
    .unwrap();
    let q = curve
        .decode_point(&hex("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5"))
        .unwrap();
    let private_key = AnyParams::EcPrivate {
        key: AnyEcPrivateKey::Secp192r1(Box::new(EcPrivateKey::new(g.clone(), d).unwrap())),
    };
    let public_key = AnyParams::EcPublic {
        key: AnyEcPublicKey::Secp192r1(Box::new(EcPublicKey::new(g, &q).unwrap())),
    };
    let params = ies(&private_key, &public_key);

    let mut ecies = cipher::get_by_name("ECIES").unwrap().cipher();
    let message = hex("1234567890abcdef");
    let sealed = cipher::encrypt(&mut ecies, &params, &message).unwrap();
    assert_eq!(
        sealed,
        hex("609ae8fe2727572da30a1d04e3dd0530de24ee89e7313f6c400992a6")
    );
    assert_eq!(
        cipher::decrypt(&mut ecies, &params, &sealed).unwrap(),
        message
    );
}
