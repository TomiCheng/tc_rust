#![cfg(feature = "ec")]

use rand::SeedableRng;
use rand::rngs::StdRng;
use tc_algo::ErrorKind;
use tc_algo::generate::key_pair::KeyPair;
use tc_algo::generate::{self, KeyGenParams};
use tc_algo::params::{AnyEcPrivateKey, AnyPrivateKey, AnyPublicKey, EcCurve};
use tc_asn1::Asn1Oid;

fn curves(pair: &KeyPair) -> (EcCurve, EcCurve) {
    let (AnyPublicKey::Ec(public), AnyPrivateKey::Ec(private)) = (&pair.public, &pair.private)
    else {
        panic!("not an EC key pair");
    };
    (public.curve(), private.curve())
}

fn generate_on(params: impl Into<KeyGenParams>) -> KeyPair {
    let mut generator = generate::key_pair::get_by_name("EC").unwrap();
    generator.init(params).unwrap();
    generator.generate().unwrap()
}

#[test]
fn a_key_pair_is_on_the_curve_asked_for() {
    for curve in [
        EcCurve::Secp224k1,
        EcCurve::Secp224r1,
        EcCurve::Secp256k1,
        EcCurve::Secp256r1,
        EcCurve::Secp384r1,
        EcCurve::Secp521r1,
        EcCurve::Sm2p256v1,
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp112r1,
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp128r1,
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp192k1,
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect233k1,
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect571r1,
    ] {
        assert_eq!(curves(&generate_on(curve)), (curve, curve));
    }
}

#[test]
fn a_size_alone_takes_the_curve_bouncy_castle_takes() {
    for (bits, curve) in [
        (224, EcCurve::Secp224r1),
        (256, EcCurve::Secp256r1),
        (384, EcCurve::Secp384r1),
        (521, EcCurve::Secp521r1),
    ] {
        let pair = generate_on(KeyGenParams::Strength { bits });
        assert_eq!(curves(&pair), (curve, curve), "{bits}");
    }
}

// 239 bits names prime239v1, which this crate does not have; 192 bits names P-192, a small curve
#[test]
fn a_size_without_a_curve_is_refused() {
    let mut generator = generate::key_pair::get_by_name("EC").unwrap();
    for bits in [
        160,
        239,
        255,
        512,
        #[cfg(not(feature = "ec-small-curves"))]
        192,
    ] {
        let error = generator
            .init(KeyGenParams::Strength { bits })
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams, "{bits}");
    }
}

#[test]
fn without_init_there_is_no_curve_to_generate_on() {
    let mut generator = generate::key_pair::get_by_name("EC").unwrap();
    let error = generator.generate().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams);
    let error = generate::key_pair::generate("EC").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams);
}

#[test]
fn the_same_seed_gives_the_same_key_pair() {
    let generate = || {
        let mut generator = generate::key_pair::get_by_name("EC").unwrap();
        generator.init(EcCurve::Secp256r1).unwrap();
        generator.with_rng(StdRng::seed_from_u64(7));
        generator.generate().unwrap()
    };
    let d = |pair: &KeyPair| match &pair.private {
        AnyPrivateKey::Ec(AnyEcPrivateKey::Secp256r1(key)) => key.d().clone(),
        _ => panic!("not a P-256 key"),
    };
    assert_eq!(d(&generate()), d(&generate()));
}

#[test]
fn the_generator_is_found_by_its_bouncy_castle_names_in_any_case() {
    for name in ["EC", "ec", "ECDH", "ECIES", "ECDHC", "ecdhc"] {
        let generator = generate::key_pair::get_by_name(name).unwrap();
        assert_eq!(generator.entry().name(), "EC", "{name}");
    }
}

// The ECDH schemes with a KDF of X9.63 and SEC 1, as Bouncy Castle maps them
#[test]
fn the_generator_is_found_by_the_oids_of_the_ecdh_kdf_schemes() {
    let entry = generate::key_pair::algorithms()
        .find(|entry| entry.name() == "EC")
        .unwrap();
    assert_eq!(entry.oids().len(), 10);
    for dotted in [
        "1.3.133.16.840.63.0.2",
        "1.3.133.16.840.63.0.3",
        "1.3.132.1.11.0",
        "1.3.132.1.11.3",
        "1.3.132.1.14.0",
        "1.3.132.1.14.3",
    ] {
        let oid: Asn1Oid = dotted.parse().unwrap();
        let generator = generate::key_pair::get_by_oid(&oid).unwrap();
        assert_eq!(generator.entry().name(), "EC", "{dotted}");
    }
    assert!(
        entry
            .to_string()
            .starts_with("EC  [dhSinglePass-stdDH-sha1kdf-scheme, ")
    );
}
