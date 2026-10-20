use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{Curve, FieldElement, Point};
use tc_f2m_curve_v2::named_curves as generic;
use tc_f2m_curve_v2::{F2mCtCurve, F2mCtPoint};
use tc_f2m_custom_v2::named_curves::{SECT163K1, SECT163R1, SECT163R2, SECT233K1, SECT233R1};
use tc_f2m_custom_v2::{SecT163FieldElement, SecT233FieldElement, SecTCtCurve};

type Ct163<'a> = &'a SecTCtCurve<SecT163FieldElement>;
type Ct233<'a> = &'a SecTCtCurve<SecT233FieldElement>;

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

// Same curve, same scalar: the specialized and the generic ladder land on the same point.
fn matches_generic<C: Curve<Scalar = PaddedBigUint>>(g: C::Point, h: F2mCtPoint<'_>, len: usize) {
    let mut state = 0x0163_0233_0163_0233;
    for _ in 0..10 {
        let k = scalar(&mut state, len);
        let (p, q) = (C::multiply(&g, &k), <&F2mCtCurve>::multiply(&h, &k));
        assert_eq!(encode(p.x()), encode(q.x()));
        assert_eq!(encode(p.y()), encode(q.y()));
    }
}

fn valid_and_of_order_n<C: Curve<Scalar = PaddedBigUint>>(g: C::Point) {
    assert!(g.is_valid());
    let n = g.curve().order().unwrap().clone();
    assert!(C::multiply(&g, &n).is_infinity());
}

fn group_law<C: Curve<Scalar = PaddedBigUint>>(g: C::Point) {
    let three = PaddedBigUint::from(3u8);
    assert!(g.add(&g) == g.twice());
    assert!(g.twice().add(&g) == C::multiply(&g, &three));
    assert!(g.three_times() == C::multiply(&g, &three));
    assert!(g.add(&g.negate()).is_infinity());
    assert!(g.add(&g.infinity()) == g);
    assert!(g.twice().is_valid());
}

#[test]
fn multiples_of_the_generator_match_the_generic_curves() {
    for (custom, generic) in [
        (SECT163K1, generic::SECT163K1),
        (SECT163R1, generic::SECT163R1),
        (SECT163R2, generic::SECT163R2),
    ] {
        let (curve, reference) = (custom.ct_curve(), generic.ct_curve());
        let h = generic.ct_generator(&reference);
        matches_generic::<Ct163<'_>>(custom.ct_generator(&curve), h, 21);
    }
    for (custom, generic) in [
        (SECT233K1, generic::SECT233K1),
        (SECT233R1, generic::SECT233R1),
    ] {
        let (curve, reference) = (custom.ct_curve(), generic.ct_curve());
        let h = generic.ct_generator(&reference);
        matches_generic::<Ct233<'_>>(custom.ct_generator(&curve), h, 30);
    }
}

#[test]
fn the_generators_are_valid_and_of_order_n() {
    for named in [SECT163K1, SECT163R1, SECT163R2] {
        let curve = named.ct_curve();
        valid_and_of_order_n::<Ct163<'_>>(named.ct_generator(&curve));
    }
    for named in [SECT233K1, SECT233R1] {
        let curve = named.ct_curve();
        valid_and_of_order_n::<Ct233<'_>>(named.ct_generator(&curve));
    }
}

#[test]
fn the_group_law_holds_on_the_generator() {
    let curve = SECT163R2.ct_curve();
    group_law::<Ct163<'_>>(SECT163R2.ct_generator(&curve));
    let curve = SECT233K1.ct_curve();
    group_law::<Ct233<'_>>(SECT233K1.ct_generator(&curve));
}
