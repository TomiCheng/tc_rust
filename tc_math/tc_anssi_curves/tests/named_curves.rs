//! FRP256v1 自洽，且 BC 給的基點編碼解得出同一個 G。

use tc_anssi_curves::*;
use tc_bigint::PaddedBigUint;
use tc_ec_core::Point;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

// G 在曲線上、n·G 是無窮遠點、餘因子如 BC；`encoded` 是 BC 給的基點編碼，要解出同一個 G
fn check_fp<const N: usize>(named: &AnssiNamedCurve<N>, cofactor: u32, encoded: &str) {
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
fn frp256v1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &FRP256V1,
        1,
        "04b6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb",
    );
}
