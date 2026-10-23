//! 金鑰與 DER 互轉：格式錯誤、結尾多出的 bytes、不認得的演算法、不是金鑰的參數，以及 CFRG 曲線的金鑰。

#![cfg(feature = "key-factory")]

use std::error::Error;

#[cfg(feature = "ed25519")]
use tc_asn1::Asn1BitString;
use tc_asn1::{Asn1Error, Asn1OctetString, Encode, EncodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x509::alg::AlgorithmIdentifier;
#[cfg(feature = "ed25519")]
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_security::params::AnyParams;
use tc_security::{AnyError, SecurityError, key_factory};

/// 沿著 source 往下找第一個 `E`。
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

#[cfg(any(feature = "x25519", feature = "ed25519"))]
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn unknown_private_key_der() -> Vec<u8> {
    PrivateKeyInfo::new(
        AlgorithmIdentifier::new("1.2.3.4".parse().unwrap()),
        Asn1OctetString::new(&[1, 2, 3]),
    )
    .encode_to_vec(&EncodingOptions::DER)
    .unwrap()
}

#[test]
fn an_unknown_key_algorithm_is_refused() {
    let Err(error) = key_factory::private_key_from_der(&unknown_private_key_der()) else {
        panic!("1.2.3.4 is no key algorithm");
    };
    assert_eq!(
        source::<SecurityError>(&error),
        Some(&SecurityError::UnknownKeyAlgorithm)
    );
}

#[test]
fn trailing_bytes_and_broken_der_are_refused() {
    let mut der = unknown_private_key_der();
    der.push(0);
    let Err(error) = key_factory::private_key_from_der(&der) else {
        panic!("trailing bytes are refused");
    };
    assert_eq!(source::<Asn1Error>(&error), Some(&Asn1Error::TrailingData));

    for der in [&[][..], &[0x30, 0x05, 0x02], &[0x04, 0x00]] {
        assert!(
            key_factory::private_key_from_der(der).is_err(),
            "{der:02x?}"
        );
        assert!(key_factory::public_key_from_der(der).is_err(), "{der:02x?}");
    }
}

#[test]
fn a_symmetric_key_is_neither_a_private_nor_a_public_key() {
    let symmetric = AnyParams::new(vec![7; 16]);
    for result in [
        key_factory::private_key_to_der(&symmetric).map(|der| der.to_vec()),
        key_factory::public_key_to_der(&symmetric),
    ] {
        let Err(error) = result else {
            panic!("a symmetric key is no asymmetric key");
        };
        assert_eq!(
            source::<SecurityError>(&error),
            Some(&SecurityError::WrongParams)
        );
    }
}

/// RFC 8410 第 10.1、10.3 節的範例：公鑰、v0 私鑰，以及帶屬性與公鑰的 v1 私鑰。
#[cfg(feature = "ed25519")]
#[test]
fn the_rfc_8410_ed25519_examples_decode_to_a_matching_key_pair() {
    let public = hex(
        "302a300506032b657003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1",
    );
    let v0 = hex(
        "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842",
    );
    let v1 = hex(concat!(
        "3072020101300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842",
        "a01f301d060a2a864886f70d01090914310f0c0d437572646c652043686169727381210019bf44096984cdfe8541ba",
        "c167dc3b96c85086aa30b6b6cb0c5c38ad703166e1",
    ));

    let Ok(AnyParams::Ed25519Public { key: ref public }) =
        key_factory::public_key_from_der(&public)
    else {
        panic!("an Ed25519 public key");
    };
    assert_eq!(
        public.a()[..],
        hex("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1")
    );
    for der in [v0, v1] {
        let Ok(AnyParams::Ed25519Private { ref key }) = key_factory::private_key_from_der(&der)
        else {
            panic!("an Ed25519 private key");
        };
        assert_eq!(
            key.k()[..],
            hex("d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842")
        );
        assert_eq!(&key.generate_public_key(), public);
    }
}

/// RFC 7748 第 6.1 節 Alice 的金鑰對；同 BC 附上公鑰。
#[cfg(feature = "x25519")]
#[test]
fn an_x25519_private_key_is_written_as_version_one_with_its_public_key() {
    let k = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let u = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let key = AnyParams::X25519Private {
        key: tc_cfrg_curves::X25519PrivateKey::new(k.clone().try_into().unwrap()),
    };

    let der = key_factory::private_key_to_der(&key).unwrap();
    let expected = [
        &hex("3051020101300506032b656e04220420")[..],
        &k,
        &hex("812100"),
        &u,
    ]
    .concat();
    assert_eq!(der[..], expected[..]);

    let Ok(AnyParams::X25519Private { ref key }) = key_factory::private_key_from_der(&der) else {
        panic!("an X25519 private key");
    };
    assert_eq!(key.k()[..], k);
}

#[cfg(all(
    feature = "x25519",
    feature = "x448",
    feature = "ed25519",
    feature = "ed448"
))]
#[test]
fn every_cfrg_key_survives_a_round_trip_through_der() {
    use tc_cfrg_curves::{Ed448PrivateKey, Ed25519PrivateKey, X448PrivateKey, X25519PrivateKey};

    let x25519 = X25519PrivateKey::new([1; 32]);
    let x448 = X448PrivateKey::new([2; 56]);
    let ed25519 = Ed25519PrivateKey::new([3; 32]);
    let ed448 = Ed448PrivateKey::new([4; 57]);
    let privates = [
        AnyParams::X25519Private {
            key: x25519.clone(),
        },
        AnyParams::X448Private { key: x448.clone() },
        AnyParams::Ed25519Private {
            key: ed25519.clone(),
        },
        AnyParams::Ed448Private { key: ed448.clone() },
    ];
    let publics = [
        AnyParams::X25519Public {
            key: x25519.generate_public_key(),
        },
        AnyParams::X448Public {
            key: x448.generate_public_key(),
        },
        AnyParams::Ed25519Public {
            key: ed25519.generate_public_key(),
        },
        AnyParams::Ed448Public {
            key: ed448.generate_public_key(),
        },
    ];

    for key in &privates {
        let der = key_factory::private_key_to_der(key).unwrap();
        let back = key_factory::private_key_from_der(&der).unwrap();
        assert_eq!(key_factory::private_key_to_der(&back).unwrap()[..], der[..]);
    }
    for key in &publics {
        let der = key_factory::public_key_to_der(key).unwrap();
        let back = key_factory::public_key_from_der(&der).unwrap();
        assert_eq!(key_factory::public_key_to_der(&back).unwrap(), der);
    }
}

/// Java 11 的 X25519／X448 私鑰沒包內層 OCTET STRING；Cryptlib 與 GnuPG 的 OID 同 BC 也收。
#[cfg(all(feature = "x25519", feature = "ed25519"))]
#[test]
fn the_variant_encodings_bc_tolerates_are_accepted() {
    let bare = PrivateKeyInfo::new(
        AlgorithmIdentifier::new("1.3.101.110".parse().unwrap()),
        Asn1OctetString::new(&[5; 32]),
    );
    let Ok(AnyParams::X25519Private { ref key }) = key_factory::private_key_from_info(&bare) else {
        panic!("a bare X25519 private key");
    };
    assert_eq!(key.k(), &[5; 32]);

    let cryptlib = PrivateKeyInfo::new(
        AlgorithmIdentifier::new("1.3.6.1.4.1.3029.1.5.1".parse().unwrap()),
        Asn1OctetString::new(&[5; 32]),
    );
    assert!(matches!(
        key_factory::private_key_from_info(&cryptlib),
        Ok(AnyParams::X25519Private { .. })
    ));

    let gnu = SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::new("1.3.6.1.4.1.11591.15.1".parse().unwrap()),
        Asn1BitString::from_bytes(&[6; 32]),
    );
    let Ok(AnyParams::Ed25519Public { ref key }) = key_factory::public_key_from_info(&gnu) else {
        panic!("a GnuPG Ed25519 public key");
    };
    assert_eq!(key.a(), &[6; 32]);
}

#[cfg(feature = "ed25519")]
#[test]
fn wrong_key_lengths_and_unused_bits_are_refused() {
    let ed25519 = || AlgorithmIdentifier::new("1.3.101.112".parse().unwrap());
    let inner = |len: usize| {
        Asn1OctetString::new(&vec![7; len])
            .encode_to_vec(&EncodingOptions::DER)
            .unwrap()
    };
    let privates = [
        PrivateKeyInfo::new(ed25519(), Asn1OctetString::new(&inner(31))),
        PrivateKeyInfo::new(ed25519(), Asn1OctetString::new(&inner(33))),
        PrivateKeyInfo::new(ed25519(), Asn1OctetString::new(&[7; 32])),
    ];
    let publics = [
        SubjectPublicKeyInfo::new(ed25519(), Asn1BitString::from_bytes(&[7; 31])),
        SubjectPublicKeyInfo::new(ed25519(), Asn1BitString::from_bits(&[7; 32], 255)),
    ];

    for info in &privates {
        assert!(key_factory::private_key_from_info(info).is_err());
    }
    for info in &publics {
        let Err(error) = key_factory::public_key_from_info(info) else {
            panic!("a malformed public key is refused");
        };
        assert_eq!(
            source::<SecurityError>(&error),
            Some(&SecurityError::InvalidKeyEncoding)
        );
    }
}
