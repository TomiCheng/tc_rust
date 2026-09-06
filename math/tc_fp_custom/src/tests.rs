use alloc::sync::Arc;

use tc_bigint::U256;
use tc_ec_core::{Curve, FieldElement, Point, WNafTable, scalar_mul, wnaf_mul, wnaf_mul_point};
use tc_fp_curve::FpCurve;

use crate::{SecP256R1Curve, SecP256R1FieldElement, SecP256R1Point, secp256r1};

fn random_scalar(state: &mut u64) -> U256 {
    let mut bytes = [0_u8; 32];
    for chunk in bytes.chunks_mut(8) {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        chunk.copy_from_slice(&state.to_le_bytes());
    }
    bytes[0] |= 0x80;
    U256::from_be_bytes(&bytes).unwrap()
}

fn assert_same_point(custom: &SecP256R1Point, generic: &tc_fp_curve::FpPoint<U256>) {
    assert_eq!(custom.encode(false), generic.encode(false));
    assert_eq!(custom.encode(true), generic.encode(true));
}

#[test]
fn specialized_curve_matches_generic_for_full_width_scalars_and_random_points() {
    let (_, custom_generator) = secp256r1();
    let (_, generic_generator) = tc_fp_curve::named_curves::secp256r1();
    let mut state = 0x5231_C057_0BAD_0001_u64;

    for _ in 0..12 {
        let point_scalar = random_scalar(&mut state);
        let scalar = random_scalar(&mut state);
        assert_eq!(point_scalar.bit_length(), 256);
        assert_eq!(scalar.bit_length(), 256);

        let custom_point = scalar_mul::<SecP256R1Curve>(&custom_generator, &point_scalar);
        let generic_point = scalar_mul::<FpCurve<U256>>(&generic_generator, &point_scalar);
        assert_same_point(&custom_point, &generic_point);

        assert_same_point(&custom_point.twice(), &generic_point.twice());
        assert_same_point(
            &custom_point.add_point(&custom_generator),
            &(&generic_point + &generic_generator),
        );
        assert_same_point(
            &scalar_mul::<SecP256R1Curve>(&custom_point, &scalar),
            &scalar_mul::<FpCurve<U256>>(&generic_point, &scalar),
        );
        assert_same_point(
            &wnaf_mul_point::<SecP256R1Curve>(&custom_point, &scalar),
            &wnaf_mul_point::<FpCurve<U256>>(&generic_point, &scalar),
        );
    }
}

#[test]
fn unchanged_generic_algorithms_run_on_the_specialized_curve() {
    let (_, generator) = secp256r1();
    let scalar = U256::from_be_bytes(&[
        0xf1, 0x42, 0x8b, 0x39, 0xc7, 0x51, 0x66, 0xa2, 0x08, 0x3d, 0xda, 0x51, 0x92, 0xe0, 0x47,
        0xb6, 0x5c, 0x82, 0xaf, 0x11, 0xd4, 0x7e, 0x30, 0x9c, 0x7b, 0x94, 0x10, 0x55, 0xe8, 0x2d,
        0x13, 0x77,
    ])
    .unwrap();
    let expected = scalar_mul::<SecP256R1Curve>(&generator, &scalar);
    assert_eq!(
        wnaf_mul_point::<SecP256R1Curve>(&generator, &scalar),
        expected
    );

    let table = WNafTable::new(&generator, 5, true);
    assert_eq!(wnaf_mul::<SecP256R1Curve>(&table, &scalar), expected);
}

#[test]
fn sec1_codec_matches_generic_curve_in_every_form() {
    let (custom_curve, custom_generator) = secp256r1();
    let (generic_curve, generic_generator) = tc_fp_curve::named_curves::secp256r1();
    for compressed in [false, true] {
        let custom_encoding = custom_generator.encode(compressed);
        let generic_encoding = generic_generator.encode(compressed);
        assert_eq!(custom_encoding, generic_encoding);
        assert_eq!(
            custom_curve.decode_point(&generic_encoding).unwrap(),
            custom_generator
        );
        assert_eq!(
            generic_curve.decode_point(&custom_encoding).unwrap(),
            generic_generator
        );

        let mut output = [0_u8; 65];
        let length = custom_generator.encode_to(compressed, &mut output).unwrap();
        assert_eq!(&output[..length], custom_encoding);
        assert!(
            custom_generator
                .encode_to(compressed, &mut output[..length - 1])
                .is_err()
        );
    }
}

#[test]
fn identity_negation_y_zero_and_projective_equality_edges_hold() {
    let (curve, generator) = secp256r1();
    let identity = curve.infinity();
    assert_eq!(generator.add_point(&identity), generator);
    assert_eq!(identity.add_point(&generator), generator);
    assert_eq!(generator.add_point(&generator.negate()), identity);
    assert_eq!(identity.twice(), identity);
    assert_eq!(identity.three_times(), identity);
    assert_eq!(identity.times_pow2(7), identity);

    let invalid_y_zero = SecP256R1Point::new(
        Arc::clone(&curve),
        SecP256R1FieldElement::ZERO,
        SecP256R1FieldElement::ZERO,
    );
    assert!(!invalid_y_zero.is_valid());
    assert_eq!(invalid_y_zero.twice(), identity);

    let doubled = generator.twice();
    assert!(!doubled.z().unwrap().is_one());
    assert_eq!(doubled, doubled.normalize());
    assert_eq!(doubled.x(), Point::x(&doubled));
    assert_eq!(doubled.y(), Point::y(&doubled));
    assert_eq!(
        <SecP256R1Curve as Curve>::coordinate_system(&curve),
        tc_ec_core::CoordinateSystem::Jacobian
    );
    assert_eq!(
        SecP256R1FieldElement::ONE.zero(),
        SecP256R1FieldElement::ZERO
    );
}
