//! wNAF 表示與乘法器的跨後端驗證。

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use tc_bigint::{BigUint, U256};
use tc_ec_core::{
    Curve, WNafTable, generate_compact_window_naf, generate_naf, generate_window_naf,
    get_naf_weight, get_window_size, scalar_mul, wnaf_mul, wnaf_mul_point,
};

use crate::named_curves::{secp256k1, secp256r1};
use crate::{CoordinateSystem, FpCurve, FpInteger, FpPoint};

type NamedCurve = fn() -> (Arc<FpCurve<U256>>, FpPoint<U256>);

fn reconstruct(digits: &[i8]) -> BigUint {
    let mut value = BigUint::from(0_u8);
    for digit in digits.iter().rev() {
        value = &value + &value;
        let magnitude = BigUint::from(digit.unsigned_abs());
        value = if *digit < 0 {
            &value - &magnitude
        } else {
            &value + &magnitude
        };
    }
    value
}

fn expand_compact(compact: &[i32]) -> Vec<i8> {
    let mut digits = Vec::new();
    let mut position = 0_usize;
    for (index, entry) in compact.iter().copied().enumerate() {
        let digit = (entry >> 16) as i8;
        let zeroes = (entry & 0xFFFF) as usize;
        position = if index == 0 {
            zeroes
        } else {
            position + zeroes + 1
        };
        digits.resize(position + 1, 0);
        digits[position] = digit;
    }
    digits
}

fn deterministic_scalar(value: &str) -> U256 {
    U256::from_str_radix(value, 16).unwrap()
}

#[test]
fn scalar_helpers_cover_dynamic_and_fixed_integers() {
    fn check<B: FpInteger>() {
        let scalar = B::from_u32(0b101101).unwrap();
        assert!(!<FpCurve<B> as Curve>::scalar_is_zero(&scalar));
        assert_eq!(<FpCurve<B> as Curve>::scalar_low_bits(&scalar, 4), 0b1101);
        assert_eq!(
            <FpCurve<B> as Curve>::scalar_shr1(&scalar),
            B::from_u32(0b10110).unwrap()
        );
        assert_eq!(
            <FpCurve<B> as Curve>::scalar_sub_digit(&scalar, 5),
            B::from_u32(40).unwrap()
        );
        assert_eq!(
            <FpCurve<B> as Curve>::scalar_sub_digit(&scalar, -3),
            B::from_u32(48).unwrap()
        );
        assert!(<FpCurve<B> as Curve>::scalar_is_zero(
            &B::from_u32(0).unwrap()
        ));
    }

    check::<BigUint>();
    check::<U256>();
}

#[test]
fn naf_and_window_naf_reconstruct_the_scalar() {
    let scalar =
        deterministic_scalar("C51F7A94D308C624B1E975A06D42F89C357E1ABCDA75398F02468ACE13579BDF");
    let naf = generate_naf::<FpCurve<U256>>(&scalar);
    assert_eq!(reconstruct(&naf), BigUint::from(scalar));
    assert!(naf.iter().all(|digit| (-1..=1).contains(digit)));
    assert!(naf.windows(2).all(|pair| pair[0] == 0 || pair[1] == 0));
    assert_eq!(
        get_naf_weight::<FpCurve<U256>>(&scalar),
        naf.iter().filter(|digit| **digit != 0).count()
    );

    for width in 2..=8 {
        let digits = generate_window_naf::<FpCurve<U256>>(width, &scalar);
        assert_eq!(reconstruct(&digits), BigUint::from(scalar), "width {width}");
        let limit = (1_i16 << (width - 1)) - 1;
        let mut previous = None;
        for (position, digit) in digits.iter().copied().enumerate() {
            if digit == 0 {
                continue;
            }
            assert_ne!(digit & 1, 0, "width {width}");
            assert!(i16::from(digit).abs() <= limit, "width {width}");
            if let Some(previous) = previous {
                assert!(position - previous >= width, "width {width}");
            }
            previous = Some(position);
        }

        let compact = generate_compact_window_naf::<FpCurve<U256>>(width, &scalar);
        assert_eq!(expand_compact(&compact), digits, "width {width}");

        let max_digits = generate_window_naf::<FpCurve<U256>>(width, &U256::MAX);
        assert_eq!(
            reconstruct(&max_digits),
            BigUint::from(U256::MAX),
            "max, width {width}"
        );
        assert_eq!(
            expand_compact(&generate_compact_window_naf::<FpCurve<U256>>(
                width,
                &U256::MAX,
            )),
            max_digits,
            "max compact, width {width}"
        );
    }
}

#[test]
fn window_size_uses_the_bc_cutoffs() {
    for (bits, expected) in [
        (0, 2),
        (12, 2),
        (13, 3),
        (40, 3),
        (41, 4),
        (120, 4),
        (121, 5),
        (336, 5),
        (337, 6),
        (896, 6),
        (897, 7),
        (2304, 7),
        (2305, 8),
    ] {
        assert_eq!(get_window_size(bits), expected, "bits {bits}");
    }
}

fn assert_named_curve(named_curve: NamedCurve, point_scalar: &U256, scalar: &U256) {
    let (base_curve, generator) = named_curve();
    let random_point = scalar_mul::<FpCurve<U256>>(&generator, point_scalar).normalize();
    let x = random_point.x().unwrap().to_big_uint();
    let y = random_point.y().unwrap().to_big_uint();

    for coordinate_system in [
        CoordinateSystem::Affine,
        CoordinateSystem::Homogeneous,
        CoordinateSystem::Jacobian,
        CoordinateSystem::JacobianModified,
    ] {
        let curve = Arc::new(
            (*base_curve)
                .clone()
                .with_coordinate_system(coordinate_system),
        );
        let point = curve.create_point(x, y);
        let expected = scalar_mul::<FpCurve<U256>>(&point, scalar);

        for width in 2..=8 {
            let table = WNafTable::new(&point, width, width % 2 == 0);
            assert_eq!(table.precomputed().len(), 1 << (width - 2));
            assert_eq!(table.precomputed_negated().is_some(), width % 2 == 0);
            assert_eq!(
                wnaf_mul::<FpCurve<U256>>(&table, scalar),
                expected,
                "{coordinate_system:?}, width {width}"
            );
        }

        assert_eq!(
            wnaf_mul_point::<FpCurve<U256>>(&point, scalar),
            expected,
            "{coordinate_system:?}, convenience"
        );
        assert_eq!(
            <FpCurve<U256> as Curve>::multiply(&point, scalar),
            expected,
            "{coordinate_system:?}, curve default"
        );
    }
}

#[test]
fn wnaf_matches_double_and_add_on_both_curves_and_all_coordinates() {
    let point_scalar =
        deterministic_scalar("91D8A4B6C308E257F13468AB9D20CFE17B5A39246E80D1C35F729ABC46801357");
    let scalar =
        deterministic_scalar("C51F7A94D308C624B1E975A06D42F89C357E1ABCDA75398F02468ACE13579BDF");
    assert_named_curve(secp256k1, &point_scalar, &scalar);
    assert_named_curve(secp256r1, &point_scalar, &scalar);
}

#[test]
fn boundary_scalars_match_double_and_add() {
    let (base_curve, generator) = secp256k1();
    let curve = Arc::new(
        (*base_curve)
            .clone()
            .with_coordinate_system(CoordinateSystem::JacobianModified),
    );
    let point = curve.create_point(
        generator.x().unwrap().to_big_uint(),
        generator.y().unwrap().to_big_uint(),
    );
    let one = U256::from(1_u8);
    let power = U256::from(0_u8).set_bit(255);
    let scalars = vec![
        U256::from(0_u8),
        one,
        U256::from(2_u8),
        *curve.order().unwrap() - one,
        power,
        power - one,
        U256::MAX,
    ];

    for scalar in scalars {
        assert_eq!(
            wnaf_mul_point::<FpCurve<U256>>(&point, &scalar),
            scalar_mul::<FpCurve<U256>>(&point, &scalar),
            "scalar {scalar:?}"
        );
    }
}
