use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{Curve, FieldElement, Point};
use tc_f2m_curve_v2::named_curves as generic;
use tc_f2m_custom_v2::named_curves::{SECT163K1, SECT163R1, SECT163R2};

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

// Same curve, same scalar: the specialized and the generic ladder land on the same point.
#[test]
fn multiples_of_the_generator_match_the_generic_curves() {
    let mut state = 0x0163_0163_0163_0163;
    for (custom, generic) in [
        (SECT163K1, generic::SECT163K1),
        (SECT163R1, generic::SECT163R1),
        (SECT163R2, generic::SECT163R2),
    ] {
        let curve = custom.ct_curve();
        let g = custom.ct_generator(&curve);
        let reference = generic.ct_curve();
        let h = generic.ct_generator(&reference);
        for _ in 0..10 {
            let k = scalar(&mut state);
            let (p, q) = (g.multiply(&k), h.multiply(&k));
            assert_eq!(encode(p.x()), encode(q.x()));
            assert_eq!(encode(p.y()), encode(q.y()));
        }
    }
}

#[test]
fn the_generators_are_valid_and_of_order_n() {
    for named in [SECT163K1, SECT163R1, SECT163R2] {
        let curve = named.ct_curve();
        let g = named.ct_generator(&curve);
        assert!(g.is_valid());
        let handle = &curve;
        assert!(g.multiply(handle.order().unwrap()).is_infinity());
    }
}

#[test]
fn the_group_law_holds_on_the_generator() {
    let curve = SECT163R2.ct_curve();
    let g = SECT163R2.ct_generator(&curve);
    let three = PaddedBigUint::from(3u8);

    assert_eq!(g.add(&g), g.twice());
    assert_eq!(g.twice().add(&g), g.multiply(&three));
    assert_eq!(g.three_times(), g.multiply(&three));
    assert!(g.subtract(&g).is_infinity());
    assert_eq!(g.add(&g.infinity()), g);
    assert!(g.twice().is_valid());
}
