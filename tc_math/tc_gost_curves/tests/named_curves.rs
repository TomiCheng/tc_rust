//! 七組參數各自自洽：G 在曲線上、n·G 是無窮遠點、餘因子如 BC；別名等於原曲線；
//! 512 paramSetA 上 RFC 7836 例 7 的私鑰乘 G 得到它給的公鑰。

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core::{Point, PrimeFieldElement};
use tc_gost_curves::*;

fn check<const N: usize>(named: &GostNamedCurve<N>, cofactor: u8) {
    let field = named.field();
    let ct_curve = named.ct_curve(&field);
    let var_curve = named.var_curve(&field);
    let g = named.ct_generator(&ct_curve);
    let h = named.var_generator(&var_curve);
    let n = ct_curve.order().unwrap();

    assert!(g.is_valid() && h.is_valid());
    assert!(g.multiply(n).is_infinity() && h.multiply(n).is_infinity());
    assert_eq!(ct_curve.cofactor(), Some(&PaddedBigUint::from(cofactor)));
    assert_eq!(g.twice().encode(true), h.twice().encode(true));
    assert_eq!(ct_curve.decode_point(&g.encode(true)), Ok(g.clone()));
}

#[test]
fn the_cryptopro_curves_are_consistent() {
    check(&GOSTR3410_2001_CRYPTOPRO_A, 1);
    check(&GOSTR3410_2001_CRYPTOPRO_B, 1);
    check(&GOSTR3410_2001_CRYPTOPRO_C, 1);
}

#[test]
fn the_tc26_curves_are_consistent_with_a_cofactor_of_four_on_two_of_them() {
    check(&TC26_GOST_3410_12_256_PARAMSET_A, 4);
    check(&TC26_GOST_3410_12_512_PARAMSET_A, 1);
    check(&TC26_GOST_3410_12_512_PARAMSET_B, 1);
    check(&TC26_GOST_3410_12_512_PARAMSET_C, 4);
}

#[test]
fn each_alias_is_the_curve_it_names() {
    assert_eq!(GOSTR3410_2001_CRYPTOPRO_XCHA, GOSTR3410_2001_CRYPTOPRO_A);
    assert_eq!(GOSTR3410_2001_CRYPTOPRO_XCHB, GOSTR3410_2001_CRYPTOPRO_C);
    assert_eq!(TC26_GOST_3410_12_256_PARAMSET_B, GOSTR3410_2001_CRYPTOPRO_A);
    assert_eq!(TC26_GOST_3410_12_256_PARAMSET_C, GOSTR3410_2001_CRYPTOPRO_B);
    assert_eq!(TC26_GOST_3410_12_256_PARAMSET_D, GOSTR3410_2001_CRYPTOPRO_C);
}

// RFC 7836 以小端序寫出整數
fn little_endian(hex: &str) -> PaddedBigUint {
    let mut bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    bytes.reverse();
    <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes).unwrap()
}

#[test]
fn the_keys_of_rfc_7836_example_7_lie_on_512_param_set_a() {
    let named = TC26_GOST_3410_12_512_PARAMSET_A;
    let field = named.field();
    let curve = named.ct_curve(&field);
    let g = named.ct_generator(&curve);
    for (d, x, y) in [
        (
            "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667",
            "aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7",
            "914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a",
        ),
        (
            "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db",
            "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651",
            "04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79",
        ),
    ] {
        let (qx, qy) = g.multiply(&little_endian(d)).affine().unwrap();
        assert_eq!(qx.to_big_uint(), little_endian(x));
        assert_eq!(qy.to_big_uint(), little_endian(y));
    }
}
