use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{CoordinateSystem, Curve, FieldElement, Point};
use tc_f2m_curve_v2::named_curves as generic;
use tc_f2m_curve_v2::{F2mVarCurve, F2mVarPoint};
use tc_f2m_custom_v2::named_curves::*;
use tc_f2m_custom_v2::*;

type Var<'a, F> = &'a SecTVarCurve<F>;

fn encode<F: FieldElement>(x: Option<F>) -> Option<Vec<u8>> {
    x.map(|x| {
        let mut bytes = vec![0; x.encoded_length()];
        x.encode_to(&mut bytes);
        bytes
    })
}

fn scalar(state: &mut u64, len: usize) -> PaddedBigUint {
    let bytes: Vec<u8> = (0..len)
        .map(|_| {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as u8
        })
        .collect();
    let Ok(k) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
    k
}

fn valid_and_of_order_n<C: Curve<Scalar = PaddedBigUint>>(g: &C::Point) {
    assert!(g.is_valid());
    let n = g.curve().order().unwrap().clone();
    assert!(C::multiply(g, &n).is_infinity());
}

fn same<P: Point>(p: &P, q: &F2mVarPoint<'_>) {
    assert_eq!(encode(p.x()), encode(q.x()));
    assert_eq!(encode(p.y()), encode(q.y()));
}

// Same curve, same scalars: the specialized lambda-projective formulas land on the points that
// the generic curve's do, and the group law holds whatever the projective scale.
fn check<C: Curve<Scalar = PaddedBigUint>>(g: C::Point, h: F2mVarPoint<'_>, len: usize) {
    valid_and_of_order_n::<C>(&g);
    let mut state = 0x0163_0233_0163_0233;
    for _ in 0..6 {
        let (j, k) = (scalar(&mut state, len), scalar(&mut state, len));
        let (p, q) = (C::multiply(&g, &j), <&F2mVarCurve>::multiply(&h, &j));
        let (r, s) = (C::multiply(&g, &k), <&F2mVarCurve>::multiply(&h, &k));
        same(&p, &q);
        same(&p.add(&r), &q.add(&s));
        same(&p.twice(), &q.twice());
        same(&p.twice_plus(&r.normalize()), &q.twice_plus(&s.normalize()));
    }
    let three = PaddedBigUint::from(3u8);
    let two = g.twice();
    assert!(g.add(&g) == two);
    assert!(two.add(&g) == C::multiply(&g, &three));
    assert!(two.add(&g) == two.normalize().add(&g));
    assert!(g.twice_plus(&g) == g.three_times());
    assert!(g.add(&g.negate()).is_infinity());
    assert!(g.add(&g.infinity()) == g);
    assert!(two.is_valid());
}

#[test]
fn every_curve_adds_and_multiplies_as_the_generic_one_does() {
    let lambda = CoordinateSystem::LambdaProjective;
    let curve = SECT163K1.var_curve();
    let reference = generic::SECT163K1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT163FieldElement>>(
        SECT163K1.var_generator(&curve),
        generic::SECT163K1.var_generator(&reference),
        21,
    );
    let curve = SECT163R1.var_curve();
    let reference = generic::SECT163R1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT163FieldElement>>(
        SECT163R1.var_generator(&curve),
        generic::SECT163R1.var_generator(&reference),
        21,
    );
    let curve = SECT163R2.var_curve();
    let reference = generic::SECT163R2
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT163FieldElement>>(
        SECT163R2.var_generator(&curve),
        generic::SECT163R2.var_generator(&reference),
        21,
    );
    let curve = SECT193R1.var_curve();
    let reference = generic::SECT193R1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT193FieldElement>>(
        SECT193R1.var_generator(&curve),
        generic::SECT193R1.var_generator(&reference),
        25,
    );
    let curve = SECT193R2.var_curve();
    let reference = generic::SECT193R2
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT193FieldElement>>(
        SECT193R2.var_generator(&curve),
        generic::SECT193R2.var_generator(&reference),
        25,
    );
    let curve = SECT233K1.var_curve();
    let reference = generic::SECT233K1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT233FieldElement>>(
        SECT233K1.var_generator(&curve),
        generic::SECT233K1.var_generator(&reference),
        30,
    );
    let curve = SECT233R1.var_curve();
    let reference = generic::SECT233R1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT233FieldElement>>(
        SECT233R1.var_generator(&curve),
        generic::SECT233R1.var_generator(&reference),
        30,
    );
    let curve = SECT239K1.var_curve();
    let reference = generic::SECT239K1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT239FieldElement>>(
        SECT239K1.var_generator(&curve),
        generic::SECT239K1.var_generator(&reference),
        30,
    );
    let curve = SECT283K1.var_curve();
    let reference = generic::SECT283K1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT283FieldElement>>(
        SECT283K1.var_generator(&curve),
        generic::SECT283K1.var_generator(&reference),
        36,
    );
    let curve = SECT283R1.var_curve();
    let reference = generic::SECT283R1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT283FieldElement>>(
        SECT283R1.var_generator(&curve),
        generic::SECT283R1.var_generator(&reference),
        36,
    );
    let curve = SECT409K1.var_curve();
    let reference = generic::SECT409K1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT409FieldElement>>(
        SECT409K1.var_generator(&curve),
        generic::SECT409K1.var_generator(&reference),
        52,
    );
    let curve = SECT409R1.var_curve();
    let reference = generic::SECT409R1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT409FieldElement>>(
        SECT409R1.var_generator(&curve),
        generic::SECT409R1.var_generator(&reference),
        52,
    );
    let curve = SECT571K1.var_curve();
    let reference = generic::SECT571K1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT571FieldElement>>(
        SECT571K1.var_generator(&curve),
        generic::SECT571K1.var_generator(&reference),
        72,
    );
    let curve = SECT571R1.var_curve();
    let reference = generic::SECT571R1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT571FieldElement>>(
        SECT571R1.var_generator(&curve),
        generic::SECT571R1.var_generator(&reference),
        72,
    );
}

#[cfg(feature = "small-curves")]
#[test]
fn every_small_curve_adds_and_multiplies_as_the_generic_one_does() {
    let lambda = CoordinateSystem::LambdaProjective;
    let curve = SECT113R1.var_curve();
    let reference = generic::SECT113R1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT113FieldElement>>(
        SECT113R1.var_generator(&curve),
        generic::SECT113R1.var_generator(&reference),
        15,
    );
    let curve = SECT113R2.var_curve();
    let reference = generic::SECT113R2
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT113FieldElement>>(
        SECT113R2.var_generator(&curve),
        generic::SECT113R2.var_generator(&reference),
        15,
    );
    let curve = SECT131R1.var_curve();
    let reference = generic::SECT131R1
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT131FieldElement>>(
        SECT131R1.var_generator(&curve),
        generic::SECT131R1.var_generator(&reference),
        17,
    );
    let curve = SECT131R2.var_curve();
    let reference = generic::SECT131R2
        .var_curve()
        .with_coordinate_system(lambda);
    check::<Var<'_, SecT131FieldElement>>(
        SECT131R2.var_generator(&curve),
        generic::SECT131R2.var_generator(&reference),
        17,
    );
}
