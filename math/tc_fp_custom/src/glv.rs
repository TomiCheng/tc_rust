//! secp256k1 GLV Type B decomposition, using BC's lattice constants.
//! This is exclusively a public-scalar optimization.
use crate::{SecP256K1Curve, SecP256K1FieldElement, SecP256K1Point};
use tc_bigint::{ArrayEncoding, BigInt, U256};
use tc_ec_core::{Curve, GlvEndomorphism, Point, PointMap};

/// secp256k1's efficient `(beta*x, y)` endomorphism.
pub struct SecP256K1Glv;
fn hex(value: &str) -> BigInt {
    BigInt::from_str_radix(value, 16).expect("GLV constant")
}
impl PointMap<SecP256K1Point> for SecP256K1Glv {
    fn map(&self, point: &SecP256K1Point) -> SecP256K1Point {
        if point.is_identity() {
            return point.clone();
        }
        let beta = U256::from_str_radix(
            "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee",
            16,
        )
        .unwrap();
        let beta = SecP256K1FieldElement::from_integer(&beta).unwrap();
        let point = point.normalize();
        Curve::create_point(
            point.curve(),
            point.x().unwrap().multiply(&beta),
            point.y().unwrap(),
        )
    }
}
impl GlvEndomorphism<SecP256K1Curve> for SecP256K1Glv {
    fn decompose_scalar(&self, scalar: &U256) -> [(U256, bool); 2] {
        let k = BigInt::from_unsigned_le_bytes(&scalar.to_le_bytes())
            % hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        let rounded = |g: BigInt| ((&k * g) + (BigInt::from(1_u8) << 271)) >> 272;
        let b1 = rounded(hex("3086d221a7d46bcde86c90e49284eb153dab"));
        let b2 = rounded(hex("e4437ed6010e88286f547fa90abfe4c42212"));
        let a = &k
            - (&b1 * hex("3086d221a7d46bcde86c90e49284eb15")
                + &b2 * hex("114ca50f7a8e2f3f657c1108d9d44cfd8"));
        let b = -(&b1 * hex("-e4437ed6010e88286f547fa90abfe4c3")
            + &b2 * hex("3086d221a7d46bcde86c90e49284eb15"));
        [a, b].map(|v| {
            (
                U256::from_le_bytes(&v.abs().to_unsigned_le_bytes()).expect("GLV magnitude fits"),
                v.is_negative(),
            )
        })
    }
}
