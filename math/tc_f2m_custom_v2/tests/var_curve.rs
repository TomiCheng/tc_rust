use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{CoordinateSystem, Curve, FieldElement, Point};
use tc_f2m_curve_v2::named_curves as generic;
use tc_f2m_curve_v2::{F2mVarCurve, F2mVarPoint};
use tc_f2m_custom_v2::named_curves::{SECT163K1, SECT163R1, SECT163R2, SECT233K1, SECT233R1};
use tc_f2m_custom_v2::{SecT163FieldElement, SecT233FieldElement, SecTVarCurve};

type Var163<'a> = &'a SecTVarCurve<SecT163FieldElement>;
type Var233<'a> = &'a SecTVarCurve<SecT233FieldElement>;

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

fn same<P: Point>(p: &P, q: &F2mVarPoint<'_>) {
    assert_eq!(encode(p.x()), encode(q.x()));
    assert_eq!(encode(p.y()), encode(q.y()));
}

// Same curve, same scalar: the specialized lambda-projective formulas land on the point that
// the generic curve does, in its affine and in its lambda-projective coordinates.
fn matches_generic<C: Curve<Scalar = PaddedBigUint>>(g: C::Point, h: F2mVarPoint<'_>, len: usize) {
    let mut state = 0x0163_0233_0163_0233;
    for _ in 0..10 {
        let (j, k) = (scalar(&mut state, len), scalar(&mut state, len));
        let (p, q) = (C::multiply(&g, &j), <&F2mVarCurve>::multiply(&h, &j));
        let (r, s) = (C::multiply(&g, &k), <&F2mVarCurve>::multiply(&h, &k));
        same(&p, &q);
        same(&p.add(&r), &q.add(&s));
        same(&p.twice(), &q.twice());
        same(&p.twice_plus(&r.normalize()), &q.twice_plus(&s.normalize()));
    }
}

fn valid_and_of_order_n<C: Curve<Scalar = PaddedBigUint>>(g: C::Point) {
    assert!(g.is_valid());
    let n = g.curve().order().unwrap().clone();
    assert!(C::multiply(&g, &n).is_infinity());
}

fn group_law<C: Curve<Scalar = PaddedBigUint>>(g: C::Point) {
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
fn multiples_and_sums_match_the_generic_curves() {
    let lambda = CoordinateSystem::LambdaProjective;
    for (custom, generic) in [
        (SECT163K1, generic::SECT163K1),
        (SECT163R1, generic::SECT163R1),
        (SECT163R2, generic::SECT163R2),
    ] {
        let curve = custom.var_curve();
        let affine = generic.var_curve();
        let projective = generic.var_curve().with_coordinate_system(lambda);
        let g = custom.var_generator(&curve);
        matches_generic::<Var163<'_>>(g.clone(), generic.var_generator(&affine), 21);
        matches_generic::<Var163<'_>>(g, generic.var_generator(&projective), 21);
    }
    for (custom, generic) in [
        (SECT233K1, generic::SECT233K1),
        (SECT233R1, generic::SECT233R1),
    ] {
        let curve = custom.var_curve();
        let affine = generic.var_curve();
        let projective = generic.var_curve().with_coordinate_system(lambda);
        let g = custom.var_generator(&curve);
        matches_generic::<Var233<'_>>(g.clone(), generic.var_generator(&affine), 30);
        matches_generic::<Var233<'_>>(g, generic.var_generator(&projective), 30);
    }
}

#[test]
fn the_generators_are_valid_and_of_order_n() {
    for named in [SECT163K1, SECT163R1, SECT163R2] {
        let curve = named.var_curve();
        valid_and_of_order_n::<Var163<'_>>(named.var_generator(&curve));
    }
    for named in [SECT233K1, SECT233R1] {
        let curve = named.var_curve();
        valid_and_of_order_n::<Var233<'_>>(named.var_generator(&curve));
    }
}

#[test]
fn the_group_law_holds_whatever_the_projective_scale() {
    let curve = SECT163R2.var_curve();
    group_law::<Var163<'_>>(SECT163R2.var_generator(&curve));
    let curve = SECT233R1.var_curve();
    group_law::<Var233<'_>>(SECT233R1.var_generator(&curve));
}
