//! wapip192v1 自洽，BC 給的基點編碼解得出同一個 G，別名就是它。

use tc_bigint::PaddedBigUint;
use tc_ec_core::Point;
use tc_wapi_curves::*;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

// G 在曲線上、n·G 是無窮遠點、餘因子如 BC；`encoded` 是 BC 給的基點編碼，要解出同一個 G
fn check_fp<const N: usize>(named: &WapiNamedCurve<N>, cofactor: u32, encoded: &str) {
    let field = named.field();
    let ct_curve = named.ct_curve(&field);
    let var_curve = named.var_curve(&field);
    let g = named.ct_generator(&ct_curve);
    let h = named.var_generator(&var_curve);
    let n = ct_curve.order().unwrap();

    assert!(g.is_valid() && h.is_valid());
    assert!(g.multiply(n).is_infinity() && h.multiply(n).is_infinity());
    assert_eq!(ct_curve.cofactor(), Some(&PaddedBigUint::from(cofactor)));
    assert_eq!(ct_curve.decode_point(&hex(encoded)), Ok(g.clone()));
    assert_eq!(g.twice().encode(true), h.twice().encode(true));
}

#[test]
fn wapip192v1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &WAPIP192V1,
        1,
        "044ad5f7048de709ad51236de65e4d4b482c836dc6e410664002bb3a02d4aaadacae24817a4ca3a1b014b5270432db27d2",
    );
}

#[test]
fn wapi192v1_is_wapip192v1() {
    assert_eq!(WAPI192V1, WAPIP192V1);
}
