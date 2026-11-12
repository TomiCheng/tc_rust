#![cfg(feature = "ec")]

use std::sync::OnceLock;

use tc_algo_old::{
    AnyEcPrivateKey, AnyEcPublicKey, AnyKeyParams, AnyParams, AnyPrivateKey, AnyPublicKey, EcCurve,
};
use tc_bigint::PaddedBigUint;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_fp_custom::{SecP256R1FieldElement, SecPCtCurve, SecPCtPoint};

// A key points into its curve, so the curve has to live for the whole program
fn p256_generator() -> SecPCtPoint<'static, SecP256R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP256R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP256R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn private_key() -> AnyEcPrivateKey {
    let key = EcPrivateKey::new(p256_generator(), PaddedBigUint::from(7u32)).unwrap();
    AnyEcPrivateKey::Secp256r1(Box::new(key))
}

// The generator itself is a point on the curve, so it serves as a public key
fn public_key() -> AnyEcPublicKey {
    let g = p256_generator();
    let key = EcPublicKey::new(g.clone(), &g).unwrap();
    AnyEcPublicKey::Secp256r1(Box::new(key))
}

#[test]
fn an_ec_key_goes_into_the_params_as_a_private_or_a_public_key() {
    let private = AnyParams::new(AnyKeyParams::Private(AnyPrivateKey::Ec(private_key())));
    let public = AnyParams::new(AnyKeyParams::Public(AnyPublicKey::Ec(public_key())));
    assert!(matches!(
        private.key,
        AnyKeyParams::Private(AnyPrivateKey::Ec(_))
    ));
    assert!(matches!(
        public.key,
        AnyKeyParams::Public(AnyPublicKey::Ec(_))
    ));
}

#[test]
fn an_ec_key_reports_its_curve() {
    assert_eq!(private_key().curve(), EcCurve::Secp256r1);
    assert_eq!(public_key().curve(), EcCurve::Secp256r1);
}

#[test]
fn debug_shows_the_curve_but_no_key_values() {
    assert_eq!(
        format!("{:?}", private_key()),
        "AnyEcPrivateKey(Secp256r1, ..)"
    );
    assert_eq!(
        format!("{:?}", public_key()),
        "AnyEcPublicKey(Secp256r1, ..)"
    );
    let params = AnyParams::new(AnyKeyParams::Private(AnyPrivateKey::Ec(private_key())));
    assert_eq!(
        format!("{params:?}"),
        "AnyParams { key: Private(Ec(..)), op: AnyOpParams { iv: None, tag_len: None, aad: None } }"
    );
}

#[test]
fn ec_keys_can_be_cloned_and_sent_between_threads() {
    fn assert_traits<T: Clone + Send + Sync + 'static>() {}
    assert_traits::<AnyEcPrivateKey>();
    assert_traits::<AnyEcPublicKey>();
}
