//! 金鑰與 DER 互轉：格式錯誤、結尾多出的 bytes、不認得的演算法與不是金鑰的參數。

#![cfg(feature = "key-factory")]

use std::error::Error;

use tc_asn1::{Asn1Error, Asn1OctetString, Encode, EncodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x509::alg::AlgorithmIdentifier;
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
