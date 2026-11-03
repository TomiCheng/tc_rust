//! 每條曲線都自洽：G 在曲線上、n·G 是無窮遠點、餘因子如 BC。BC 以座標給基點，沒有編碼可比。

use tc_bigint::PaddedBigUint;
use tc_dstu4145_curves::*;
use tc_ec_core::{Curve, Point};
use tc_f2m_curve::F2mVarCurve;

#[allow(dead_code)]
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

// G 在曲線上、n·G 是無窮遠點、餘因子如 BC；`encoded` 是 BC 給的基點編碼時，要解出同一個 G
fn check_f2m<const N: usize>(named: &Dstu4145NamedCurve<N>, cofactor: u32, encoded: Option<&str>) {
    let ct_curve = named.ct_curve();
    let var_curve = named.var_curve();
    let g = named.ct_generator(&ct_curve);
    let h = named.var_generator(&var_curve);
    let n = ct_curve.order().unwrap();

    assert!(g.is_valid() && h.is_valid());
    assert!(g.multiply(n).is_infinity());
    assert!(<&F2mVarCurve as Curve>::multiply(&h, n).is_infinity());
    assert_eq!(ct_curve.cofactor(), Some(&PaddedBigUint::from(cofactor)));
    if let Some(encoded) = encoded {
        assert_eq!(ct_curve.decode_point(&hex(encoded)), Ok(g.clone()));
    }
    assert_eq!(g.twice().encode(true), h.twice().encode(true));
}

#[test]
fn dstu4145_163_holds_together() {
    check_f2m(&DSTU4145_163, 2, None);
}

#[test]
fn dstu4145_167_holds_together() {
    check_f2m(&DSTU4145_167, 2, None);
}

#[test]
fn dstu4145_173_holds_together() {
    check_f2m(&DSTU4145_173, 4, None);
}

#[test]
fn dstu4145_179_holds_together() {
    check_f2m(&DSTU4145_179, 2, None);
}

#[test]
fn dstu4145_191_holds_together() {
    check_f2m(&DSTU4145_191, 2, None);
}

#[test]
fn dstu4145_233_holds_together() {
    check_f2m(&DSTU4145_233, 2, None);
}

#[test]
fn dstu4145_257_holds_together() {
    check_f2m(&DSTU4145_257, 4, None);
}

#[test]
fn dstu4145_307_holds_together() {
    check_f2m(&DSTU4145_307, 2, None);
}

#[test]
fn dstu4145_367_holds_together() {
    check_f2m(&DSTU4145_367, 2, None);
}

#[test]
fn dstu4145_431_holds_together() {
    check_f2m(&DSTU4145_431, 2, None);
}
