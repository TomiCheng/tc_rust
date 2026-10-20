use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{Curve, FieldElement, Point};
use tc_f2m_curve_v2::named_curves as generic;
use tc_f2m_curve_v2::{F2mVarCurve, F2mVarPoint};
use tc_f2m_custom_v2::named_curves::{SECT163K1, SECT163R1, SECT163R2};
use tc_f2m_custom_v2::{SecT163FieldElement, SecTVarCurve, SecTVarPoint};

fn encode<F: FieldElement>(x: Option<F>) -> Option<Vec<u8>> {
    x.map(|x| {
        let mut bytes = vec![0; x.encoded_length()];
        x.encode_to(&mut bytes);
        bytes
    })
}

fn scalar(state: &mut u64) -> PaddedBigUint {
    let bytes: Vec<u8> = (0..21)
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

type Custom<'a> = &'a SecTVarCurve<SecT163FieldElement>;

fn same(p: &SecTVarPoint<'_, SecT163FieldElement>, q: &F2mVarPoint<'_>) {
    assert_eq!(encode(p.x()), encode(q.x()));
    assert_eq!(encode(p.y()), encode(q.y()));
}

// Same curve, same scalar: the specialized lambda-projective formulas land on the point that
// the generic curve's affine ones, worked out independently, do.
#[test]
fn multiples_and_sums_match_the_generic_curves() {
    let mut state = 0x0163_0163_0163_0163;
    for (custom, generic) in [
        (SECT163K1, generic::SECT163K1),
        (SECT163R1, generic::SECT163R1),
        (SECT163R2, generic::SECT163R2),
    ] {
        let curve = custom.var_curve();
        let g = custom.var_generator(&curve);
        let reference = generic.var_curve();
        let h = generic.var_generator(&reference);
        for _ in 0..10 {
            let (j, k) = (scalar(&mut state), scalar(&mut state));
            let (p, q) = (Custom::multiply(&g, &j), <&F2mVarCurve>::multiply(&h, &j));
            let (r, s) = (Custom::multiply(&g, &k), <&F2mVarCurve>::multiply(&h, &k));
            same(&p, &q);
            same(&p.add(&r), &q.add(&s));
            same(&p.twice(), &q.twice());
            same(&p.twice_plus(&r.normalize()), &q.twice_plus(&s.normalize()));
            assert!(p.add(&r).is_on_curve());
        }
    }
}

#[test]
fn the_generators_are_valid_and_of_order_n() {
    for named in [SECT163K1, SECT163R1, SECT163R2] {
        let curve = named.var_curve();
        let g = named.var_generator(&curve);
        assert!(g.is_valid());
        let handle = &curve;
        assert!(Custom::multiply(&g, handle.order().unwrap()).is_infinity());
    }
}

#[test]
fn the_group_law_holds_whatever_the_projective_scale() {
    let curve = SECT163R2.var_curve();
    let g = SECT163R2.var_generator(&curve);
    let three = PaddedBigUint::from(3u8);

    let two = g.twice();
    assert_eq!(g.add(&g), two);
    assert_eq!(two.add(&g), Custom::multiply(&g, &three));
    assert_eq!(two.add(&g), two.normalize().add(&g));
    assert_eq!(g.twice_plus(&g), g.three_times());
    assert!(g.subtract(&g).is_infinity());
    assert_eq!(g.add(&g.infinity()), g);
    assert!(two.is_valid());
}
