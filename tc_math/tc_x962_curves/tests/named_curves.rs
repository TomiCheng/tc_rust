//! 每條曲線都自洽，且 BC 給的基點編碼解得出同一個 G。

use tc_bigint::PaddedBigUint;
use tc_ec_core::{Curve, Point};
use tc_f2m_curve::F2mVarCurve;
use tc_x962_curves::*;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

// G 在曲線上、n·G 是無窮遠點、餘因子如 BC；`encoded` 是 BC 給的基點編碼，要解出同一個 G
fn check_fp<const N: usize>(named: &X962FpNamedCurve<N>, cofactor: u32, encoded: &str) {
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

// G 在曲線上、n·G 是無窮遠點、餘因子如 BC；`encoded` 是 BC 給的基點編碼時，要解出同一個 G
fn check_f2m<const N: usize>(named: &X962F2mNamedCurve<N>, cofactor: u32, encoded: Option<&str>) {
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
fn prime192v2_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &PRIME192V2,
        1,
        "03eea2bae7e1497842f2de7769cfe9c989c072ad696f48034a",
    );
}

#[test]
fn prime192v3_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &PRIME192V3,
        1,
        "027d29778100c65a1da1783716588dce2b8b4aee8e228f1896",
    );
}

#[test]
fn prime239v1_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &PRIME239V1,
        1,
        "020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf",
    );
}

#[test]
fn prime239v2_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &PRIME239V2,
        1,
        "0238af09d98727705120c921bb5e9e26296a3cdcf2f35757a0eafd87b830e7",
    );
}

#[test]
fn prime239v3_holds_together_and_has_bouncy_castles_base_point() {
    check_fp(
        &PRIME239V3,
        1,
        "036768ae8e18bb92cfcf005c949aa2c6d94853d0e660bbf854b1c9505fe95a",
    );
}

#[test]
fn c2pnb163v1_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2PNB163V1,
        2,
        Some("0307af69989546103d79329fcc3d74880f33bbe803cb"),
    );
}

#[test]
fn c2pnb163v2_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2PNB163V2,
        2,
        Some("030024266e4eb5106d0a964d92c4860e2671db9b6cc5"),
    );
}

#[test]
fn c2pnb163v3_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2PNB163V3,
        2,
        Some("0202f9f87b7c574d0bdecf8a22e6524775f98cdebdcb"),
    );
}

#[test]
fn c2pnb176w1_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2PNB176W1,
        65390,
        Some("038d16c2866798b600f9f08bb4a8e860f3298ce04a5798"),
    );
}

#[test]
fn c2tnb191v1_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2TNB191V1,
        2,
        Some("0236b3daf8a23206f9c4f299d7b21a9c369137f2c84ae1aa0d"),
    );
}

#[test]
fn c2tnb191v2_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2TNB191V2,
        4,
        Some("023809b2b7cc1b28cc5a87926aad83fd28789e81e2c9e3bf10"),
    );
}

#[test]
fn c2tnb191v3_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2TNB191V3,
        6,
        Some("03375d4ce24fde434489de8746e71786015009e66e38a926dd"),
    );
}

#[test]
fn c2pnb208w1_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2PNB208W1,
        65096,
        Some("0289fdfbe4abe193df9559ecf07ac0ce78554e2784eb8c1ed1a57a"),
    );
}

#[test]
fn c2tnb239v1_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2TNB239V1,
        4,
        Some("0257927098fa932e7c0a96d3fd5b706ef7e5f5c156e16b7e7c86038552e91d"),
    );
}

#[test]
fn c2tnb239v2_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2TNB239V2,
        6,
        Some("0228f9d04e900069c8dc47a08534fe76d2b900b7d7ef31f5709f200c4ca205"),
    );
}

#[test]
fn c2tnb239v3_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2TNB239V3,
        10,
        Some("0370f6e9d04d289c4e89913ce3530bfde903977d42b146d539bf1bde4e9c92"),
    );
}

#[test]
fn c2pnb272w1_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2PNB272W1,
        65286,
        Some("026108babb2ceebcf787058a056cbe0cfe622d7723a289e08a07ae13ef0d10d171dd8d"),
    );
}

#[test]
fn c2pnb304w1_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2PNB304W1,
        65070,
        Some("02197b07845e9be2d96adb0f5f3c7f2cffbd7a3eb8b6fec35c7fd67f26ddf6285a644f740a2614"),
    );
}

#[test]
fn c2tnb359v1_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2TNB359V1,
        76,
        Some(
            "033c258ef3047767e7ede0f1fdaa79daee3841366a132e163aced4ed2401df9c6bdcde98e8e707c07a2239b1b097",
        ),
    );
}

#[test]
fn c2pnb368w1_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2PNB368W1,
        65392,
        Some(
            "021085e2755381dccce3c1557afa10c2f0c0c2825646c5b34a394cbcfa8bc16b22e7e789e927be216f02e1fb136a5f",
        ),
    );
}

#[test]
fn c2tnb431r1_holds_together_and_has_bouncy_castles_base_point() {
    check_f2m(
        &C2TNB431R1,
        10080,
        Some(
            "02120fc05d3c67a99de161d2f4092622feca701be4f50f4758714e8a87bbf2a658ef8c21e7c5efe965361f6c2999c0c247b0dbd70ce6b7",
        ),
    );
}
