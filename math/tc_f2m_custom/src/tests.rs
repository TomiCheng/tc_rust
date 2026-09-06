use alloc::{sync::Arc, vec};

use tc_bigint::{U256, U384, U1024};
use tc_binpoly::{BinPolyMultiplier, FixedBinaryPoly};
use tc_ec_core::scalar_mul;
use tc_f2m_curve::{F2mCurve, F2mInteger, F2mPoint, F2mPolynomial};

use crate::*;

#[derive(Clone, Copy)]
enum Reduction {
    Trinomial(usize),
    Pentanomial(usize, usize, usize),
}

fn multiplier(m: usize, reduction: Reduction) -> BinPolyMultiplier {
    match reduction {
        Reduction::Trinomial(k) => BinPolyMultiplier::trinomial(m, k).unwrap(),
        Reduction::Pentanomial(k1, k2, k3) => {
            BinPolyMultiplier::pentanomial(m, k1, k2, k3).unwrap()
        }
    }
}

fn field_matches_generic<S: BinaryFieldSpec<N>, P: F2mPolynomial, const N: usize>(
    m: usize,
    reduction: Reduction,
    seed: u64,
) {
    let multiplier = multiplier(m, reduction);
    let mut state = seed;
    for _ in 0..8 {
        let mut x = [0_u64; N];
        let mut y = [0_u64; N];
        for limb in &mut x {
            *limb = next(&mut state);
        }
        for limb in &mut y {
            *limb = next(&mut state);
        }
        let top_bits = m & 63;
        if top_bits != 0 {
            x[N - 1] &= (1_u64 << top_bits) - 1;
            y[N - 1] &= (1_u64 << top_bits) - 1;
        }
        x[0] |= 1;

        let specialized = P::from_limb_slice(multiplier.clone(), &x).unwrap();
        let specialized_y = P::from_limb_slice(multiplier.clone(), &y).unwrap();
        let generic = FixedBinaryPoly::from_limbs(multiplier.clone(), x).unwrap();
        let generic_y = FixedBinaryPoly::from_limbs(multiplier.clone(), y).unwrap();

        assert_eq!(
            specialized.multiply(&specialized_y).unwrap().as_limbs(),
            generic.multiply(&generic_y).unwrap().as_limbs()
        );
        assert_eq!(
            specialized.multiply(&specialized_y).unwrap().as_limbs(),
            SpecializedBinaryField::<S, N>::multiply_reference(&x, &y)
        );
        assert_eq!(specialized.square().as_limbs(), generic.square().as_limbs());
        assert_eq!(
            specialized.invert().unwrap().as_limbs(),
            generic.invert().unwrap().as_limbs()
        );

        let root = specialized.sqrt();
        assert!(root.square() == specialized);
        assert_eq!(root.as_limbs(), generic.sqrt().as_limbs());
    }
}

fn curve_matches_generic<P: F2mPolynomial, B: F2mInteger, const N: usize>(
    custom: (Arc<F2mCurve<P, B>>, F2mPoint<P, B>),
    m: usize,
    reduction: Reduction,
    seed: u64,
) {
    let (custom_curve, custom_g) = custom;
    let a = custom_curve.a().to_integer::<B>();
    let b = custom_curve.b().to_integer::<B>();
    let order = custom_curve.order().cloned();
    let cofactor = custom_curve.cofactor().cloned();
    let generic_curve = Arc::new(match reduction {
        Reduction::Trinomial(k) => {
            F2mCurve::<FixedBinaryPoly<N>, B>::trinomial(m, k, a, b, order, cofactor).unwrap()
        }
        Reduction::Pentanomial(k1, k2, k3) => {
            F2mCurve::<FixedBinaryPoly<N>, B>::pentanomial(m, k1, k2, k3, a, b, order, cofactor)
                .unwrap()
        }
    });
    let generic_g = generic_curve.decode_point(&custom_g.encode(false)).unwrap();

    assert!(custom_g.is_valid());
    assert_eq!(custom_g.encode(false), generic_g.encode(false));
    assert_eq!(
        custom_g.twice().encode(false),
        generic_g.twice().encode(false)
    );
    assert_eq!(
        custom_g.three_times().encode(false),
        generic_g.three_times().encode(false)
    );

    let scalar = full_width_scalar::<B>(m, seed);
    assert_eq!(scalar.bit_length(), m);
    let custom_result = scalar_mul::<F2mCurve<P, B>>(&custom_g, &scalar);
    let generic_result = scalar_mul::<F2mCurve<FixedBinaryPoly<N>, B>>(&generic_g, &scalar);
    assert_eq!(custom_result.encode(false), generic_result.encode(false));
    assert_eq!(
        custom_curve
            .decode_point(&custom_result.encode(true))
            .unwrap(),
        custom_result
    );
}

fn koblitz_wtnaf_matches_reference<P: F2mPolynomial, B: F2mInteger>(
    point: F2mPoint<P, B>,
    bits: usize,
    seed: u64,
) {
    let scalar = full_width_scalar::<B>(bits, seed);
    let expected = scalar_mul::<F2mCurve<P, B>>(&point, &scalar);
    let table = WTauNafTable::new(&point);
    assert_eq!(wtnaf_mul(&table, &scalar), expected);
    assert_eq!(
        <F2mCurve<P, B> as tc_ec_core::Curve>::multiply(&point, &scalar),
        expected
    );
}

fn full_width_scalar<B: F2mInteger>(bits: usize, seed: u64) -> B {
    let mut state = seed;
    let mut bytes = vec![0_u8; bits.div_ceil(8)];
    for byte in &mut bytes {
        *byte = next(&mut state) as u8;
    }
    let high_bits = bits & 7;
    if high_bits == 0 {
        bytes[0] |= 0x80;
    } else {
        bytes[0] &= (1_u8 << high_bits) - 1;
        bytes[0] |= 1_u8 << (high_bits - 1);
    }
    match B::from_unsigned_be_bytes(&bytes) {
        Ok(value) => value,
        Err(_) => panic!("test scalar fits the selected integer type"),
    }
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn all_nine_specialized_fields_match_fixed_binpoly() {
    field_matches_generic::<SecT113Spec, SecT113Poly, 2>(113, Reduction::Trinomial(9), 0x1130_0001);
    field_matches_generic::<SecT131Spec, SecT131Poly, 3>(
        131,
        Reduction::Pentanomial(2, 3, 8),
        0x1310_0001,
    );
    field_matches_generic::<SecT163Spec, SecT163Poly, 3>(
        163,
        Reduction::Pentanomial(3, 6, 7),
        0x1630_0001,
    );
    field_matches_generic::<SecT193Spec, SecT193Poly, 4>(
        193,
        Reduction::Trinomial(15),
        0x1930_0001,
    );
    field_matches_generic::<SecT233Spec, SecT233Poly, 4>(
        233,
        Reduction::Trinomial(74),
        0x2330_0001,
    );
    field_matches_generic::<SecT239Spec, SecT239Poly, 4>(
        239,
        Reduction::Trinomial(158),
        0x2390_0001,
    );
    field_matches_generic::<SecT283Spec, SecT283Poly, 5>(
        283,
        Reduction::Pentanomial(5, 7, 12),
        0x2830_0001,
    );
    field_matches_generic::<SecT409Spec, SecT409Poly, 7>(
        409,
        Reduction::Trinomial(87),
        0x4090_0001,
    );
    field_matches_generic::<SecT571Spec, SecT571Poly, 9>(
        571,
        Reduction::Pentanomial(2, 5, 10),
        0x5710_0001,
    );
}

#[test]
fn all_eighteen_curves_match_the_generic_field_backend() {
    curve_matches_generic::<_, U256, 2>(sect113r1(), 113, Reduction::Trinomial(9), 0x1131);
    curve_matches_generic::<_, U256, 2>(sect113r2(), 113, Reduction::Trinomial(9), 0x1132);
    curve_matches_generic::<_, U256, 3>(sect131r1(), 131, Reduction::Pentanomial(2, 3, 8), 0x1311);
    curve_matches_generic::<_, U256, 3>(sect131r2(), 131, Reduction::Pentanomial(2, 3, 8), 0x1312);
    curve_matches_generic::<_, U256, 3>(sect163k1(), 163, Reduction::Pentanomial(3, 6, 7), 0x1630);
    curve_matches_generic::<_, U256, 3>(sect163r1(), 163, Reduction::Pentanomial(3, 6, 7), 0x1631);
    curve_matches_generic::<_, U256, 3>(sect163r2(), 163, Reduction::Pentanomial(3, 6, 7), 0x1632);
    curve_matches_generic::<_, U256, 4>(sect193r1(), 193, Reduction::Trinomial(15), 0x1931);
    curve_matches_generic::<_, U256, 4>(sect193r2(), 193, Reduction::Trinomial(15), 0x1932);
    curve_matches_generic::<_, U256, 4>(sect233k1(), 233, Reduction::Trinomial(74), 0x2330);
    curve_matches_generic::<_, U256, 4>(sect233r1(), 233, Reduction::Trinomial(74), 0x2331);
    curve_matches_generic::<_, U256, 4>(sect239k1(), 239, Reduction::Trinomial(158), 0x2390);
    curve_matches_generic::<_, U384, 5>(sect283k1(), 283, Reduction::Pentanomial(5, 7, 12), 0x2830);
    curve_matches_generic::<_, U384, 5>(sect283r1(), 283, Reduction::Pentanomial(5, 7, 12), 0x2831);
    curve_matches_generic::<_, U1024, 7>(sect409k1(), 409, Reduction::Trinomial(87), 0x4090);
    curve_matches_generic::<_, U1024, 7>(sect409r1(), 409, Reduction::Trinomial(87), 0x4091);
    curve_matches_generic::<_, U1024, 9>(
        sect571k1(),
        571,
        Reduction::Pentanomial(2, 5, 10),
        0x5710,
    );
    curve_matches_generic::<_, U1024, 9>(
        sect571r1(),
        571,
        Reduction::Pentanomial(2, 5, 10),
        0x5711,
    );
}

#[test]
fn field_aliases_expose_static_kernels() {
    let x = [1_u64, 0];
    assert_eq!(SecT113Field::square(&x), x);
    assert_eq!(SecT113Field::multiply(&x, &x), x);
}

#[test]
fn all_six_koblitz_curves_use_reduced_wtnaf() {
    koblitz_wtnaf_matches_reference(sect163k1().1, 163, 0x1630_7A0F);
    koblitz_wtnaf_matches_reference(sect233k1().1, 233, 0x2330_7A0F);
    koblitz_wtnaf_matches_reference(sect239k1().1, 239, 0x2390_7A0F);
    koblitz_wtnaf_matches_reference(sect283k1().1, 283, 0x2830_7A0F);
    koblitz_wtnaf_matches_reference(sect409k1().1, 409, 0x4090_7A0F);
    koblitz_wtnaf_matches_reference(sect571k1().1, 571, 0x5710_7A0F);
}
