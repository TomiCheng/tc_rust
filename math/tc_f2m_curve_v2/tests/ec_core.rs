mod common;

use common::{GX, GY, SYSTEMS, bytes, int, sect163r2, sect163r2_ct};
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{Curve, FieldElement, Point, algo, wnaf};
use tc_f2m_curve_v2::{F2mCtCurve, F2mVarCurve};

fn check_the_shared_algorithms<C: Curve<Scalar = PaddedBigUint>>(curve: C, g: &C::Point) {
    assert!(g.is_valid());
    let mut sum = g.infinity();
    for k in 0..25 {
        assert!(C::multiply(g, &int(k)) == sum, "k = {k}");
        assert!(wnaf::wnaf_mul_point::<C>(g, &int(k)) == sum, "k = {k}");
        sum = sum.add(g);
    }

    let q = C::multiply(g, &int(7));
    let expected = C::multiply(g, &int(38));
    assert!(wnaf::sum_of_two_multiplies::<C>(g, &int(3), &q, &int(5)).unwrap() == expected);
    assert!(wnaf::shamirs_trick::<C>(g, &int(3), &q, &int(5)).unwrap() == expected);
    assert!(g.twice_plus(&q) == C::multiply(g, &int(9)));
    assert!(q.add(&g.negate()) == C::multiply(g, &int(6)));
    assert!(algo::clean_point(curve.clone(), g).unwrap() == *g);

    let mut points: Vec<C::Point> = (1..6).map(|k| C::multiply(g, &int(k))).collect();
    let originals = points.clone();
    algo::normalize_all(&mut points).unwrap();
    for (point, original) in points.iter().zip(&originals) {
        assert!(point == original);
        assert!(point.projective_z().is_none_or(|z| z.is_one()));
    }

    let mut inverses: Vec<C::Field> = points.iter().map(|p| p.x().unwrap()).collect();
    let xs = inverses.clone();
    algo::montgomery_trick(&mut inverses, None).unwrap();
    for (x, inverse) in xs.iter().zip(&inverses) {
        assert!(x.multiply(inverse).is_one());
    }
}

#[test]
fn the_core_algorithms_run_on_every_variable_time_coordinate_system() {
    for system in SYSTEMS {
        let curve = sect163r2(system);
        let g = curve.create_point(&bytes(GX), &bytes(GY)).unwrap();
        check_the_shared_algorithms(&curve, &g);
    }
}

#[test]
fn the_core_algorithms_run_on_the_constant_time_curve() {
    let curve = sect163r2_ct();
    let g = curve.create_point(&bytes(GX), &bytes(GY)).unwrap();
    check_the_shared_algorithms(&curve, &g);
}

#[test]
fn both_sets_reach_the_same_affine_multiples() {
    let (var, ct) = (sect163r2(SYSTEMS[1]), sect163r2_ct());
    let g = var.create_point(&bytes(GX), &bytes(GY)).unwrap();
    let h = ct.create_point(&bytes(GX), &bytes(GY)).unwrap();
    for k in [int(5), int(1 << 40), common::integer(common::LARGE[2])] {
        let (p, q) = (
            <&F2mVarCurve as Curve>::multiply(&g, &k),
            <&F2mCtCurve as Curve>::multiply(&h, &k),
        );
        assert!(p.x() == q.x() && p.y() == q.y());
        let (p2, q2) = (p.twice().add(&g), q.twice().add(&h));
        assert!(p2.x() == q2.x() && p2.y() == q2.y());
    }
}
