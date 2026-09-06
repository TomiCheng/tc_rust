use alloc::sync::Arc;

use tc_bigint::{
    ArrayEncoding, BigUint, BitOps, FromPrimitive, ModAdd, ModMul, ModSub, U256, U384,
};
use tc_ec_core::{CoordinateSystem, Curve, Point, WNafTable, scalar_mul, wnaf_mul, wnaf_mul_point};
use tc_fp_curve::{FpCurve, FpInteger};

use crate::specialized_curve::{SpecializedCurve, named_curve};
use crate::specialized_field::{PrimeFieldSpec, SpecializedField, SpecializedFieldElement};
use crate::specialized_point::SpecializedPoint;
use crate::{
    SecP128R1Spec, SecP160K1Spec, SecP160R1Spec, SecP160R2Spec, SecP192K1Spec, SecP192R1Spec,
    SecP224K1Spec, SecP224R1Spec, SecP256K1Spec, SecP256R1Curve, SecP256R1FieldElement,
    SecP256R1Point, SecP384R1Spec, SecP521R1Spec, secp128r1, secp160k1, secp160r1, secp160r2,
    secp192k1, secp192r1, secp224k1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1,
};

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
fn secp384r1_scalar_multiplication_matches_rfc6979_key_pair() {
    // RFC 6979 A.2.6 的 NIST P-384 key pair，直接錨定完整 `x * G` 座標。
    let (_, generator) = secp384r1();
    let scalar = U384::from_str_radix(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
        16,
    )
    .unwrap();
    let point = generator.mul_double_and_add(&scalar);
    assert_eq!(
        point.x().unwrap().to_integer(),
        U384::from_str_radix(
            "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
            16,
        )
        .unwrap()
    );
    assert_eq!(
        point.y().unwrap().to_integer(),
        U384::from_str_radix(
            "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
            16,
        )
        .unwrap()
    );
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
    assert_eq!(Curve::zero(curve.as_ref()), SecP256R1FieldElement::ZERO);
    assert_eq!(Curve::one(curve.as_ref()), SecP256R1FieldElement::ONE);
}

fn bigint<const N: usize>(words: &[u32; N]) -> BigUint {
    BigUint::from_unsigned_le_u32(words).expect("u32 magnitude is non-negative")
}

fn canonical_words<const N: usize>(value: &BigUint) -> [u32; N] {
    let mut words = [0_u32; N];
    value
        .write_unsigned_le_u32(&mut words)
        .expect("reduced field value fits its limb width");
    words
}

fn assert_specialized_field<S: PrimeFieldSpec<N>, const N: usize>() {
    let modulus = bigint(&S::P);
    let mut state = 0x8A5C_91E7_D00D_0001_u64 ^ S::BITS as u64;
    for _ in 0..48 {
        let mut left_words = [0_u32; N];
        let mut right_words = [0_u32; N];
        for word in left_words.iter_mut().chain(right_words.iter_mut()) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *word = state as u32;
        }
        let left_big = bigint(&left_words) % &modulus;
        let right_big = bigint(&right_words) % &modulus;
        let left = canonical_words(&left_big);
        let right = canonical_words(&right_big);

        assert_eq!(
            bigint(&SpecializedField::<S, N>::add(&left, &right)),
            left_big.mod_add(&right_big, &modulus),
            "{} add",
            S::NAME
        );
        assert_eq!(
            bigint(&SpecializedField::<S, N>::subtract(&left, &right)),
            left_big.mod_sub(&right_big, &modulus),
            "{} subtract",
            S::NAME
        );
        assert_eq!(
            bigint(&SpecializedField::<S, N>::multiply(&left, &right)),
            left_big.mod_mul(&right_big, &modulus),
            "{} multiply",
            S::NAME
        );
        assert_eq!(
            bigint(&SpecializedField::<S, N>::square(&left)),
            left_big.mod_mul(&left_big, &modulus),
            "{} square",
            S::NAME
        );
    }
}

fn integer<S: PrimeFieldSpec<N>, const N: usize>(words: &[u32]) -> S::Integer {
    S::Integer::from_unsigned_le_u32(words)
        .unwrap_or_else(|_| panic!("{} constant fits integer", S::NAME))
}

fn assert_specialized_curve<S: PrimeFieldSpec<N>, const N: usize>(
    pair: (Arc<SpecializedCurve<S, N>>, SpecializedPoint<S, N>),
) where
    S::Integer: FpInteger,
{
    let (custom_curve, custom_generator) = pair;
    let q = integer::<S, N>(&S::P);
    let a = integer::<S, N>(&S::A);
    let b = integer::<S, N>(&S::B);
    let order = integer::<S, N>(&S::ORDER);
    let one = S::Integer::from_u32(1).expect("one fits every curve integer");
    let generic_curve = Arc::new(
        FpCurve::new(q, a, b, Some(order.clone()), Some(one))
            .with_coordinate_system(CoordinateSystem::Jacobian),
    );
    let generic_generator =
        generic_curve.create_point(integer::<S, N>(&S::GX), integer::<S, N>(&S::GY));

    assert!(custom_generator.is_valid(), "{} generator", S::NAME);
    assert_eq!(
        custom_generator.encode(false),
        generic_generator.encode(false)
    );
    assert_eq!(
        custom_generator.encode(true),
        generic_generator.encode(true)
    );
    assert_eq!(
        custom_curve
            .decode_point(&generic_generator.encode(true))
            .expect("generic compressed point decodes"),
        custom_generator
    );
    assert_eq!(
        generic_curve
            .decode_point(&custom_generator.encode(false))
            .expect("custom uncompressed point decodes"),
        generic_generator
    );

    let point_scalar = order.clone() - &S::Integer::from_u32(17).unwrap();
    let scalar = order - &S::Integer::from_u32(257).unwrap();
    assert!(
        point_scalar.bit_length() >= S::BITS,
        "{} full-width point scalar",
        S::NAME
    );
    let custom_point = scalar_mul::<SpecializedCurve<S, N>>(&custom_generator, &point_scalar);
    let generic_point = scalar_mul::<FpCurve<S::Integer>>(&generic_generator, &point_scalar);
    assert_eq!(custom_point.encode(false), generic_point.encode(false));
    assert_eq!(
        custom_point.twice().encode(false),
        generic_point.twice().encode(false)
    );
    assert_eq!(
        custom_point.add_point(&custom_generator).encode(false),
        (&generic_point + &generic_generator).encode(false)
    );
    assert_eq!(
        scalar_mul::<SpecializedCurve<S, N>>(&custom_point, &scalar).encode(false),
        scalar_mul::<FpCurve<S::Integer>>(&generic_point, &scalar).encode(false)
    );
    assert_eq!(
        wnaf_mul_point::<SpecializedCurve<S, N>>(&custom_point, &scalar).encode(false),
        wnaf_mul_point::<FpCurve<S::Integer>>(&generic_point, &scalar).encode(false)
    );

    let identity = custom_curve.infinity();
    assert_eq!(custom_generator.add_point(&identity), custom_generator);
    assert_eq!(
        custom_generator.add_point(&custom_generator.negate()),
        identity
    );
}

macro_rules! verify_curve {
    ($spec:ty, $n:literal, $constructor:ident) => {{
        assert_specialized_field::<$spec, $n>();
        assert_specialized_curve::<$spec, $n>($constructor());
    }};
}

#[test]
fn sm2_matches_generic_montgomery_oracles() {
    assert_specialized_field::<crate::Sm2P256V1Spec, 8>();
    assert_specialized_curve::<crate::Sm2P256V1Spec, 8>(crate::sm2p256v1());
}

#[test]
fn all_remaining_sec_prime_curves_match_generic_montgomery_oracles() {
    verify_curve!(SecP128R1Spec, 4, secp128r1);
    verify_curve!(SecP160K1Spec, 5, secp160k1);
    verify_curve!(SecP160R1Spec, 5, secp160r1);
    verify_curve!(SecP160R2Spec, 5, secp160r2);
    verify_curve!(SecP192K1Spec, 6, secp192k1);
    verify_curve!(SecP192R1Spec, 6, secp192r1);
    verify_curve!(SecP224K1Spec, 7, secp224k1);
    verify_curve!(SecP224R1Spec, 7, secp224r1);
    verify_curve!(SecP256K1Spec, 8, secp256k1);
    verify_curve!(SecP384R1Spec, 12, secp384r1);
    verify_curve!(SecP521R1Spec, 17, secp521r1);
}

#[test]
fn shared_curve_factories_replace_field_element_receiver_factories() {
    let (curve, _) = named_curve::<SecP256K1Spec, 8>();
    assert_eq!(
        Curve::zero(curve.as_ref()),
        SpecializedFieldElement::<SecP256K1Spec, 8>::ZERO
    );
    assert_eq!(
        Curve::one(curve.as_ref()),
        SpecializedFieldElement::<SecP256K1Spec, 8>::ONE
    );
}
