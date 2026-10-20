use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{Curve, FieldElement, Point};
use tc_f2m_curve_v2::named_curves as generic;
use tc_f2m_curve_v2::{F2mCtCurve, F2mCtPoint};
use tc_f2m_custom_v2::named_curves::*;
use tc_f2m_custom_v2::*;

type Ct<'a, F> = &'a SecTCtCurve<F>;

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

// Same curve, same scalar: the specialized and the generic ladder land on the same point, and
// the group law holds on the generator.
fn check<C: Curve<Scalar = PaddedBigUint>>(g: C::Point, h: F2mCtPoint<'_>, len: usize) {
    valid_and_of_order_n::<C>(&g);
    let mut state = 0x0163_0233_0163_0233;
    for _ in 0..8 {
        let k = scalar(&mut state, len);
        let (p, q) = (C::multiply(&g, &k), <&F2mCtCurve>::multiply(&h, &k));
        assert_eq!(encode(p.x()), encode(q.x()));
        assert_eq!(encode(p.y()), encode(q.y()));
    }
    let three = PaddedBigUint::from(3u8);
    assert!(g.add(&g) == g.twice());
    assert!(g.twice().add(&g) == C::multiply(&g, &three));
    assert!(g.three_times() == C::multiply(&g, &three));
    assert!(g.add(&g.negate()).is_infinity());
    assert!(g.add(&g.infinity()) == g);
    assert!(g.twice().is_valid());
}

#[test]
fn every_curve_multiplies_as_the_generic_one_does() {
    let (curve, reference) = (SECT163K1.ct_curve(), generic::SECT163K1.ct_curve());
    check::<Ct<'_, SecT163FieldElement>>(
        SECT163K1.ct_generator(&curve),
        generic::SECT163K1.ct_generator(&reference),
        21,
    );
    let (curve, reference) = (SECT163R1.ct_curve(), generic::SECT163R1.ct_curve());
    check::<Ct<'_, SecT163FieldElement>>(
        SECT163R1.ct_generator(&curve),
        generic::SECT163R1.ct_generator(&reference),
        21,
    );
    let (curve, reference) = (SECT163R2.ct_curve(), generic::SECT163R2.ct_curve());
    check::<Ct<'_, SecT163FieldElement>>(
        SECT163R2.ct_generator(&curve),
        generic::SECT163R2.ct_generator(&reference),
        21,
    );
    let (curve, reference) = (SECT193R1.ct_curve(), generic::SECT193R1.ct_curve());
    check::<Ct<'_, SecT193FieldElement>>(
        SECT193R1.ct_generator(&curve),
        generic::SECT193R1.ct_generator(&reference),
        25,
    );
    let (curve, reference) = (SECT193R2.ct_curve(), generic::SECT193R2.ct_curve());
    check::<Ct<'_, SecT193FieldElement>>(
        SECT193R2.ct_generator(&curve),
        generic::SECT193R2.ct_generator(&reference),
        25,
    );
    let (curve, reference) = (SECT233K1.ct_curve(), generic::SECT233K1.ct_curve());
    check::<Ct<'_, SecT233FieldElement>>(
        SECT233K1.ct_generator(&curve),
        generic::SECT233K1.ct_generator(&reference),
        30,
    );
    let (curve, reference) = (SECT233R1.ct_curve(), generic::SECT233R1.ct_curve());
    check::<Ct<'_, SecT233FieldElement>>(
        SECT233R1.ct_generator(&curve),
        generic::SECT233R1.ct_generator(&reference),
        30,
    );
    let (curve, reference) = (SECT239K1.ct_curve(), generic::SECT239K1.ct_curve());
    check::<Ct<'_, SecT239FieldElement>>(
        SECT239K1.ct_generator(&curve),
        generic::SECT239K1.ct_generator(&reference),
        30,
    );
    let (curve, reference) = (SECT283K1.ct_curve(), generic::SECT283K1.ct_curve());
    check::<Ct<'_, SecT283FieldElement>>(
        SECT283K1.ct_generator(&curve),
        generic::SECT283K1.ct_generator(&reference),
        36,
    );
    let (curve, reference) = (SECT283R1.ct_curve(), generic::SECT283R1.ct_curve());
    check::<Ct<'_, SecT283FieldElement>>(
        SECT283R1.ct_generator(&curve),
        generic::SECT283R1.ct_generator(&reference),
        36,
    );
    let (curve, reference) = (SECT409K1.ct_curve(), generic::SECT409K1.ct_curve());
    check::<Ct<'_, SecT409FieldElement>>(
        SECT409K1.ct_generator(&curve),
        generic::SECT409K1.ct_generator(&reference),
        52,
    );
    let (curve, reference) = (SECT409R1.ct_curve(), generic::SECT409R1.ct_curve());
    check::<Ct<'_, SecT409FieldElement>>(
        SECT409R1.ct_generator(&curve),
        generic::SECT409R1.ct_generator(&reference),
        52,
    );
    let (curve, reference) = (SECT571K1.ct_curve(), generic::SECT571K1.ct_curve());
    check::<Ct<'_, SecT571FieldElement>>(
        SECT571K1.ct_generator(&curve),
        generic::SECT571K1.ct_generator(&reference),
        72,
    );
    let (curve, reference) = (SECT571R1.ct_curve(), generic::SECT571R1.ct_curve());
    check::<Ct<'_, SecT571FieldElement>>(
        SECT571R1.ct_generator(&curve),
        generic::SECT571R1.ct_generator(&reference),
        72,
    );
}

#[cfg(feature = "small-curves")]
#[test]
fn every_small_curve_multiplies_as_the_generic_one_does() {
    let (curve, reference) = (SECT113R1.ct_curve(), generic::SECT113R1.ct_curve());
    check::<Ct<'_, SecT113FieldElement>>(
        SECT113R1.ct_generator(&curve),
        generic::SECT113R1.ct_generator(&reference),
        15,
    );
    let (curve, reference) = (SECT113R2.ct_curve(), generic::SECT113R2.ct_curve());
    check::<Ct<'_, SecT113FieldElement>>(
        SECT113R2.ct_generator(&curve),
        generic::SECT113R2.ct_generator(&reference),
        15,
    );
    let (curve, reference) = (SECT131R1.ct_curve(), generic::SECT131R1.ct_curve());
    check::<Ct<'_, SecT131FieldElement>>(
        SECT131R1.ct_generator(&curve),
        generic::SECT131R1.ct_generator(&reference),
        17,
    );
    let (curve, reference) = (SECT131R2.ct_curve(), generic::SECT131R2.ct_curve());
    check::<Ct<'_, SecT131FieldElement>>(
        SECT131R2.ct_generator(&curve),
        generic::SECT131R2.ct_generator(&reference),
        17,
    );
}
