use alloc::sync::Arc;

use tc_bigint::{U256, U384};
use tc_ec_core::{Curve, SecretCurve, SecretField, scalar_mul};
use tc_ecdh::{EcdhBasicAgreement, EcdhError, EcdhRawAgreement, EcdhScalar, EcdhcBasicAgreement};

extern crate alloc;

fn u256(value: &str) -> U256 {
    U256::from_str_radix(value, 16).unwrap()
}

fn u384(value: &str) -> U384 {
    U384::from_str_radix(value, 16).unwrap()
}

fn hex_bytes(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn assert_basic_symmetry<C>(curve: Arc<C>, generator: C::Point)
where
    C: SecretCurve<Scalar = U256>,
    C::Field: SecretField,
    C::Scalar: EcdhScalar,
{
    let alice_d = U256::from(7_u8);
    let bob_d = U256::from(11_u8);
    let alice_public = scalar_mul::<C>(&generator, &alice_d);
    let bob_public = scalar_mul::<C>(&generator, &bob_d);
    let alice = EcdhBasicAgreement::new(curve.clone(), alice_d).unwrap();
    let bob = EcdhBasicAgreement::new(curve, bob_d).unwrap();

    assert_eq!(
        alice.calculate_agreement(&bob_public).unwrap(),
        bob.calculate_agreement(&alice_public).unwrap()
    );
}

#[test]
fn basic_agreement_is_symmetric_on_prime_and_binary_curves() {
    let (curve, generator) = tc_fp_curve::named_curves::secp256r1();
    assert_basic_symmetry(curve, generator);

    let (curve, generator) = tc_fp_custom::secp256k1();
    assert_basic_symmetry(curve, generator);

    let (curve, generator) = tc_f2m_custom::sect233k1();
    assert_basic_symmetry(curve, generator);
}

#[test]
fn nist_cavp_p256_count_zero_matches_expected_z() {
    // NIST CAVP KAS_ECC_CDH_PrimitiveTest P-256 COUNT = 0。
    let (curve, _) = tc_fp_curve::named_curves::secp256r1();
    let peer = curve.create_point(
        u256("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287"),
        u256("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac"),
    );
    let agreement = EcdhRawAgreement::new(
        curve,
        u256("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534"),
    )
    .unwrap();

    assert_eq!(
        agreement.calculate_agreement(&peer).unwrap(),
        hex_bytes("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b")
    );
}

#[test]
fn nist_cavp_p384_count_zero_matches_expected_z() {
    // NIST CAVP KAS_ECC_CDH_PrimitiveTest P-384 COUNT = 0。
    let (curve, _) = tc_fp_custom::secp384r1();
    let peer = curve
        .create_point(
            u384(
                "a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272\
                 734466b400091adbf2d68c58e0c50066",
            ),
            u384(
                "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915e\
                 d0905a32b060992b468c64766fc8437a",
            ),
        )
        .unwrap();
    let agreement = EcdhRawAgreement::new(
        curve,
        u384(
            "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774\
             ad463b205da88cf699ab4d43c9cf98a1",
        ),
    )
    .unwrap();

    assert_eq!(
        agreement.calculate_agreement(&peer).unwrap(),
        hex_bytes(
            "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457\
             e5621e766c40a2e3d4d6a04b25e533f1",
        )
    );
}

fn assert_basic_matches_cofactor<C>(curve: Arc<C>, generator: C::Point)
where
    C: SecretCurve<Scalar = U256>,
    C::Field: SecretField,
    C::Scalar: EcdhScalar,
{
    let d = U256::from(13_u8);
    let peer = scalar_mul::<C>(&generator, &U256::from(17_u8));
    let basic = EcdhBasicAgreement::new(curve.clone(), d).unwrap();
    let cofactor = EcdhcBasicAgreement::new(curve, d).unwrap();

    assert_eq!(
        basic.calculate_agreement(&peer).unwrap(),
        cofactor.calculate_agreement(&peer).unwrap()
    );
}

#[test]
fn basic_and_cofactor_variants_match_exactly_when_h_is_one() {
    let (curve, generator) = tc_fp_curve::named_curves::secp256r1();
    assert_basic_matches_cofactor(curve, generator);

    let (curve, generator) = tc_fp_custom::secp256k1();
    assert_basic_matches_cofactor(curve, generator);
}

#[test]
fn basic_and_cofactor_variants_differ_when_h_is_four() {
    let (curve, generator) = tc_f2m_custom::sect233k1();
    let d = U256::from(13_u8);
    let peer = scalar_mul::<tc_f2m_custom::SecT233K1Curve>(&generator, &U256::from(17_u8));
    let basic = EcdhBasicAgreement::new(curve.clone(), d).unwrap();
    let cofactor = EcdhcBasicAgreement::new(curve, d).unwrap();

    assert_ne!(
        basic.calculate_agreement(&peer).unwrap(),
        cofactor.calculate_agreement(&peer).unwrap()
    );
}

#[test]
fn identity_and_off_curve_public_keys_are_rejected() {
    let (curve, _) = tc_fp_curve::named_curves::secp256r1();
    let agreement = EcdhBasicAgreement::new(curve.clone(), U256::from(7_u8)).unwrap();
    let identity = curve.identity();
    let off_curve = curve.create_point(U256::zero(), U256::zero());

    assert_eq!(
        agreement.calculate_agreement(&identity),
        Err(EcdhError::InvalidPublicKey)
    );
    assert_eq!(
        agreement.calculate_agreement(&off_curve),
        Err(EcdhError::InvalidPublicKey)
    );
}

#[test]
fn generic_and_specialized_p256_backends_produce_the_same_secret() {
    let d = U256::from(19_u8);
    let peer_d = U256::from(23_u8);
    let (generic_curve, generic_generator) = tc_fp_curve::named_curves::secp256r1();
    let generic_peer = scalar_mul::<tc_fp_curve::FpCurve<U256>>(&generic_generator, &peer_d);
    let generic = EcdhBasicAgreement::new(generic_curve, d)
        .unwrap()
        .calculate_agreement(&generic_peer)
        .unwrap();

    let (specialized_curve, specialized_generator) = tc_fp_custom::secp256r1();
    let specialized_peer =
        scalar_mul::<tc_fp_custom::SecP256R1Curve>(&specialized_generator, &peer_d);
    let specialized = EcdhBasicAgreement::new(specialized_curve, d)
        .unwrap()
        .calculate_agreement(&specialized_peer)
        .unwrap();

    assert_eq!(generic, specialized);
}

#[test]
fn raw_binary_agreement_uses_the_field_width() {
    let (curve, generator) = tc_f2m_custom::sect233k1();
    let peer = scalar_mul::<tc_f2m_custom::SecT233K1Curve>(&generator, &U256::from(11_u8));
    let agreement = EcdhRawAgreement::new(curve, U256::from(7_u8)).unwrap();

    assert_eq!(agreement.agreement_size(), 30);
    assert_eq!(agreement.calculate_agreement(&peer).unwrap().len(), 30);
}
