//! EC 金鑰與 DER 互轉：OpenSSL 的金鑰、產生的金鑰，以及不支援的曲線參數與不合格的金鑰。

#![cfg(all(feature = "key-factory", feature = "ec"))]

use std::error::Error;

use tc_asn1::{Asn1OctetString, Asn1Oid, Encode, EncodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x9::ec::EcPrivateKey as EcPrivateKeyStructure;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_security::generate::{self, KeyGenParams};
use tc_security::params::{AnyParams, EcCurve};
use tc_security::{AnyError, SecurityError, key_factory};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

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

fn oid(dotted: &str) -> Asn1Oid {
    dotted.parse().unwrap()
}

/// OpenSSL 3.5 產生的金鑰：`openssl pkcs8 -topk8` 的私鑰（`ECPrivateKey` 不帶曲線）、同一把金鑰照 BC
/// 寫出的私鑰（帶曲線與公鑰，OpenSSL 讀得回同一把公鑰）、`openssl pkey -pubout` 的公鑰，以及
/// `-ec_conv_form compressed` 的壓縮點公鑰。
struct Vector {
    curve: EcCurve,
    openssl: &'static str,
    bc: &'static str,
    spki: &'static str,
    compressed: Option<&'static str>,
}

const P256: Vector = Vector {
    curve: EcCurve::Secp256r1,
    openssl: concat!(
        "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e27f3682f93f80d7f35d7a3d",
        "381dae2bb409b3b5d240b487a8571299efaf91b1a1440342000498c8c2a2872e6787664c30a7dc573e253cac2c261556",
        "ed5b22598920cb3c25bec657770272b3e218a7a211ec1f5280062200949f8e3db03fd658f3cfcdccab62",
    ),
    bc: concat!(
        "308193020100301306072a8648ce3d020106082a8648ce3d030107047930770201010420e27f3682f93f80d7f35d7a3d",
        "381dae2bb409b3b5d240b487a8571299efaf91b1a00a06082a8648ce3d030107a1440342000498c8c2a2872e6787664c",
        "30a7dc573e253cac2c261556ed5b22598920cb3c25bec657770272b3e218a7a211ec1f5280062200949f8e3db03fd658",
        "f3cfcdccab62",
    ),
    spki: concat!(
        "3059301306072a8648ce3d020106082a8648ce3d0301070342000498c8c2a2872e6787664c30a7dc573e253cac2c2615",
        "56ed5b22598920cb3c25bec657770272b3e218a7a211ec1f5280062200949f8e3db03fd658f3cfcdccab62",
    ),
    compressed: Some(concat!(
        "3039301306072a8648ce3d020106082a8648ce3d0301070322000298c8c2a2872e6787664c30a7dc573e253cac2c2615",
        "56ed5b22598920cb3c25be",
    )),
};

const SM2: Vector = Vector {
    curve: EcCurve::Sm2p256v1,
    openssl: concat!(
        "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b02010104201e6be4e8061ea6c82803694d",
        "7e849977fdb713b6a5d1a81ed07e6cfba4463498a14403420004d628e5a685d8aae2ef77834befb31ddb9f42f66602bc",
        "6b8a41a566cab3813b7417fa39d559dccb324f1ed8e4e2787fdde6e74c5cc051f5d47697bf87ed3cb5bc",
    ),
    bc: concat!(
        "308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104201e6be4e8061ea6c82803694d",
        "7e849977fdb713b6a5d1a81ed07e6cfba4463498a00a06082a811ccf5501822da14403420004d628e5a685d8aae2ef77",
        "834befb31ddb9f42f66602bc6b8a41a566cab3813b7417fa39d559dccb324f1ed8e4e2787fdde6e74c5cc051f5d47697",
        "bf87ed3cb5bc",
    ),
    spki: concat!(
        "3059301306072a8648ce3d020106082a811ccf5501822d03420004d628e5a685d8aae2ef77834befb31ddb9f42f66602",
        "bc6b8a41a566cab3813b7417fa39d559dccb324f1ed8e4e2787fdde6e74c5cc051f5d47697bf87ed3cb5bc",
    ),
    compressed: None,
};

#[cfg(feature = "ec-f2m")]
const SECT233K1: Vector = Vector {
    curve: EcCurve::Sect233k1,
    openssl: concat!(
        "307d020100301006072a8648ce3d020106052b8104001a04663064020101041d5a7d73eb3c8bd601c23e44ffc6bd57c8",
        "cc7e9f02bbd1dee571e0e1bc66a140033e00040165f2a039b5daeb1515419dd22c6f53d15b7aff931188a32c1c3a681c",
        "f401eed80a859e89a972f510a95f7b9de5c8a5b435e6901f05dd1a361b7174",
    ),
    bc: concat!(
        "308186020100301006072a8648ce3d020106052b8104001a046f306d020101041d5a7d73eb3c8bd601c23e44ffc6bd57",
        "c8cc7e9f02bbd1dee571e0e1bc66a00706052b8104001aa140033e00040165f2a039b5daeb1515419dd22c6f53d15b7a",
        "ff931188a32c1c3a681cf401eed80a859e89a972f510a95f7b9de5c8a5b435e6901f05dd1a361b7174",
    ),
    spki: concat!(
        "3052301006072a8648ce3d020106052b8104001a033e00040165f2a039b5daeb1515419dd22c6f53d15b7aff931188a3",
        "2c1c3a681cf401eed80a859e89a972f510a95f7b9de5c8a5b435e6901f05dd1a361b7174",
    ),
    compressed: Some(concat!(
        "3034301006072a8648ce3d020106052b8104001a032000020165f2a039b5daeb1515419dd22c6f53d15b7aff931188a3",
        "2c1c3a681cf4",
    )),
};

fn vectors() -> Vec<Vector> {
    vec![
        P256,
        SM2,
        #[cfg(feature = "ec-f2m")]
        SECT233K1,
    ]
}

#[test]
fn openssl_keys_decode_and_are_written_as_bc_writes_them() {
    for vector in vectors() {
        let Ok(AnyParams::EcPrivate { ref key }) =
            key_factory::private_key_from_der(&hex(vector.openssl))
        else {
            panic!("{:?}: an EC private key", vector.curve);
        };
        assert_eq!(key.curve(), vector.curve);
        let der = key_factory::private_key_to_der(&AnyParams::EcPrivate { key: key.clone() });
        assert_eq!(der.unwrap()[..], hex(vector.bc)[..], "{:?}", vector.curve);

        let mut spkis = vec![vector.spki];
        spkis.extend(vector.compressed);
        for spki in spkis {
            let public = key_factory::public_key_from_der(&hex(spki)).unwrap();
            let AnyParams::EcPublic { key } = &public else {
                panic!("{:?}: an EC public key", vector.curve);
            };
            assert_eq!(key.curve(), vector.curve);
            assert_eq!(
                key_factory::public_key_to_der(&public).unwrap(),
                hex(vector.spki),
                "{:?}",
                vector.curve
            );
        }
    }
}

#[test]
fn generated_keys_survive_a_round_trip_through_der() {
    let curves = [
        EcCurve::Secp256r1,
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp112r1,
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect571r1,
    ];
    for curve in curves {
        let mut generator = generate::get_by_name("EC").unwrap().generator();
        generator.init(&KeyGenParams::Ec { curve }).unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();

        let der = key_factory::private_key_to_der(&private).unwrap();
        let back = key_factory::private_key_from_der(&der).unwrap();
        assert_eq!(
            key_factory::private_key_to_der(&back).unwrap()[..],
            der[..],
            "{curve:?}"
        );
        let der = key_factory::public_key_to_der(&public).unwrap();
        let back = key_factory::public_key_from_der(&der).unwrap();
        assert_eq!(
            key_factory::public_key_to_der(&back).unwrap(),
            der,
            "{curve:?}"
        );
    }
}

/// 只收具名曲線：沒有參數、明確的曲線參數（這裡以 NULL 的 implicitlyCA 代表）與不認得的曲線都拒絕。
#[test]
fn keys_without_a_known_named_curve_are_refused() {
    let id_ec_public_key = oid("1.2.840.10045.2.1");
    let structure = EcPrivateKeyStructure::new(Asn1OctetString::new(&[1; 32]))
        .unwrap()
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap();
    for algorithm in [
        AlgorithmIdentifier::new(id_ec_public_key.clone()),
        AlgorithmIdentifier::with_null(id_ec_public_key.clone()),
        AlgorithmIdentifier::with_parameters(id_ec_public_key.clone(), oid("1.2.3.4")),
    ] {
        let info = PrivateKeyInfo::new(algorithm, Asn1OctetString::new(&structure));
        let Err(error) = key_factory::private_key_from_info(&info) else {
            panic!("no named curve, no key");
        };
        assert_eq!(
            source::<SecurityError>(&error),
            Some(&SecurityError::UnknownKeyAlgorithm)
        );
    }
}

#[test]
fn a_scalar_out_of_range_and_a_point_off_the_curve_are_refused() {
    let p256 =
        AlgorithmIdentifier::with_parameters(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7"));
    let n = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    for d in [vec![0; 32], n] {
        let structure = EcPrivateKeyStructure::new(Asn1OctetString::new(&d))
            .unwrap()
            .encode_to_vec(&EncodingOptions::DER)
            .unwrap();
        let info = PrivateKeyInfo::new(p256.clone(), Asn1OctetString::new(&structure));
        assert!(key_factory::private_key_from_info(&info).is_err());
    }

    let mut spki = hex(P256.spki);
    *spki.last_mut().unwrap() ^= 1;
    assert!(key_factory::public_key_from_der(&spki).is_err());
}
