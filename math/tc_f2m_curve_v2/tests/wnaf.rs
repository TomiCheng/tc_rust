mod common;

use common::{
    GX, LARGE, N, SYSTEMS, Var, bytes, double_and_add, generator, int, integer, sect163r2,
};
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::algo::AlgorithmError;
use tc_ec_core_v2::wnaf::{
    WNafTable, shamirs_trick, sum_of_multiplies, sum_of_two_multiplies, wnaf_mul, wnaf_mul_point,
};
use tc_ec_core_v2::{CoordinateSystem, FieldElement, Point};
use tc_f2m_curve_v2::{F2mVarCurve, F2mVarPoint};

fn scalars() -> Vec<PaddedBigUint> {
    LARGE
        .iter()
        .map(|k| integer(k))
        .chain([int(0), int(1), int(2), int(255)])
        .collect()
}

#[test]
fn a_table_holds_the_odd_multiples_and_their_negations() {
    for system in SYSTEMS {
        let curve = sect163r2(system);
        let g = generator(&curve);
        for width in 2..=6 {
            let table = WNafTable::new(&g, width, true);
            assert_eq!(table.precomputed().len(), 1 << (width - 2));
            let negated = table.precomputed_negated().unwrap();
            for (i, (point, negation)) in table.precomputed().iter().zip(negated).enumerate() {
                let odd = double_and_add(&g, &int(2 * i as u64 + 1));
                assert!(
                    *point == odd && *negation == odd.negate(),
                    "w = {width}, i = {i}"
                );
                assert!(point.projective_z().is_none_or(|z| z.is_one()));
            }
        }
    }
}

#[test]
fn wnaf_multiplication_matches_double_and_add_for_every_width() {
    for system in SYSTEMS {
        let curve = sect163r2(system);
        let g = generator(&curve);
        for width in 2..=8 {
            for negated in [false, true] {
                let table = WNafTable::new(&g, width, negated);
                for k in scalars() {
                    assert!(
                        wnaf_mul::<Var<'_>>(&table, &k) == double_and_add(&g, &k),
                        "{system:?}, w = {width}"
                    );
                }
            }
        }
        for k in scalars() {
            assert!(wnaf_mul_point::<Var<'_>>(&g, &k) == double_and_add(&g, &k));
        }
        assert!(wnaf_mul_point::<Var<'_>>(&g, &integer(N)).is_infinity());
    }
}

fn points(curve: &F2mVarCurve) -> (F2mVarPoint<'_>, F2mVarPoint<'_>) {
    let g = generator(curve);
    let q = wnaf_mul_point::<Var<'_>>(&g, &integer(LARGE[0]));
    (g, q)
}

#[test]
fn shamir_and_the_sums_match_separate_multiplications() {
    for system in SYSTEMS {
        let curve = sect163r2(system);
        let (g, q) = points(&curve);
        for a in &scalars() {
            for b in &scalars() {
                let expected = double_and_add(&g, a).add(&double_and_add(&q, b));
                assert!(shamirs_trick::<Var<'_>>(&g, a, &q, b).unwrap() == expected);
                assert!(sum_of_two_multiplies::<Var<'_>>(&g, a, &q, b).unwrap() == expected);
            }
        }

        let many: Vec<_> = (1..5)
            .map(|i| double_and_add(&g, &int(i * 1000 + 7)))
            .collect();
        let ks: Vec<_> = LARGE.iter().map(|k| integer(k)).collect();
        let expected = many.iter().zip(&ks).fold(curve.infinity(), |sum, (p, k)| {
            sum.add(&double_and_add(p, k))
        });
        assert!(sum_of_multiplies::<Var<'_>>(&many, &ks).unwrap() == expected);
    }
}

#[test]
fn the_sums_reject_mismatched_lengths_curves_and_invalid_points() {
    let curve = sect163r2(CoordinateSystem::LambdaProjective);
    let (g, q) = points(&curve);
    let k = integer(LARGE[0]);
    let empty: [F2mVarPoint<'_>; 0] = [];
    assert_eq!(
        sum_of_multiplies::<Var<'_>>(&empty, &[]).unwrap_err(),
        AlgorithmError::InvalidLength
    );
    assert_eq!(
        sum_of_multiplies::<Var<'_>>(&[g.clone(), q], core::slice::from_ref(&k)).unwrap_err(),
        AlgorithmError::InvalidLength
    );

    let off_curve = curve.create_point(&bytes(GX), &bytes(GX)).unwrap();
    assert_eq!(
        sum_of_two_multiplies::<Var<'_>>(&g, &k, &off_curve, &k).unwrap_err(),
        AlgorithmError::InvalidPoint
    );
    assert_eq!(
        shamirs_trick::<Var<'_>>(&off_curve, &k, &g, &k).unwrap_err(),
        AlgorithmError::InvalidPoint
    );

    let elsewhere = F2mVarCurve::new(
        common::field(),
        &bytes(common::ONE),
        &bytes(common::ONE),
        None,
        None,
    )
    .unwrap()
    .with_coordinate_system(CoordinateSystem::LambdaProjective);
    let stranger = elsewhere.infinity();
    assert_eq!(
        shamirs_trick::<Var<'_>>(&g, &k, &stranger, &k).unwrap_err(),
        AlgorithmError::CurveMismatch
    );
    assert_eq!(
        sum_of_multiplies::<Var<'_>>(&[g.clone(), stranger], &[k.clone(), k]).unwrap_err(),
        AlgorithmError::CurveMismatch
    );
    assert!(g.x().is_some_and(|x| !x.is_zero()));
}
