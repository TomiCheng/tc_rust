//! Standard named elliptic curves (parameter tables + builders).
//!
//! A lightweight stand-in for Bouncy Castle's `ECNamedCurveTable` / `SecNamedCurves`:
//! it holds the published parameters of well-known curves and builds a ready-to-use
//! curve plus its base point. No ASN.1 / X9 / OID machinery — just the field
//! parameters, `a`, `b`, order `n`, cofactor `h`, and the encoded base point `G`.
//!
//! Because `FpCurve` and `F2mCurve` are distinct concrete types (there is no common
//! `EcCurve` trait yet — that is deferred until generic curve algorithms need it),
//! each curve is exposed as its own function returning the concrete `(Arc<curve>,
//! point)` pair, rather than a single heterogeneous `by_name` table.

use alloc::sync::Arc;

use crate::big_integer::BigInteger;
use crate::ec::f2m_curve::F2mCurve;
use crate::ec::f2m_point::F2mPoint;
use crate::ec::fp_curve::FpCurve;
use crate::ec::fp_point::FpPoint;

/// The SEC 2 **secp256k1** curve (`y² = x³ + 7` over GF(p)), with its base point `G`.
///
/// Returns `(Arc<FpCurve>, G)`; the curve carries the group order `n` and cofactor
/// `h = 1`.
pub fn secp256k1() -> (Arc<FpCurve>, FpPoint) {
    // p = 2^256 − 2^32 − 977
    let p = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    let n = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    let curve = Arc::new(FpCurve::new(
        p,
        BigInteger::from_u32(0),       // a = 0
        BigInteger::from_u32(7),       // b = 7
        Some(n),                       // 群階 n
        Some(BigInteger::from_u32(1)), // cofactor h = 1
    ));
    let gx = h("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    let gy = h("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    let g = curve.create_point(gx, gy);
    (curve, g)
}

/// The SEC 2 **secp256r1** curve — NIST **P-256** — (`y² = x³ + ax + b` over GF(p)),
/// with its base point `G`. `a = p − 3`; cofactor `h = 1`.
///
/// Its prime is byte-aligned with a non-all-ones top word, so field reduction takes
/// the Barrett path (unlike secp256k1's pseudo-Mersenne).
pub fn secp256r1() -> (Arc<FpCurve>, FpPoint) {
    // p = 2^224·(2^32 − 1) + 2^192 + 2^96 − 1
    let p = h("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    let a = h("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"); // p − 3
    let b = h("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    let n = h("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(BigInteger::from_u32(1))));
    let gx = h("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    let gy = h("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    let g = curve.create_point(gx, gy);
    (curve, g)
}

/// The SEC 2 **sect163k1** Koblitz curve (`y² + xy = x³ + x² + 1` over GF(2¹⁶³),
/// reduced by `x¹⁶³ + x⁷ + x⁶ + x³ + 1`), with its base point `G`. `a = b = 1`;
/// cofactor `h = 2`.
pub fn sect163k1() -> (Arc<F2mCurve>, F2mPoint) {
    let n = h("04000000000000000000020108A2E0CC0D99F8A5EF");
    let curve = Arc::new(F2mCurve::pentanomial(
        163,
        3,
        6,
        7,
        BigInteger::from_u32(1),       // a = 1
        BigInteger::from_u32(1),       // b = 1
        Some(n),                       // 群階 n
        Some(BigInteger::from_u32(2)), // cofactor h = 2
    ));
    let gx = h("02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8");
    let gy = h("0289070FB05D38FF58321F2E800536D538CCDAA3D9");
    let g = curve.create_point(gx, gy);
    (curve, g)
}

// --- 其餘 SEC 2 質數曲線（參數抄自 bc SecNamedCurves）---

/// SEC 2 **secp192k1** Koblitz 質數曲線（a=0, b=3, h=1）。
pub fn secp192k1() -> (Arc<FpCurve>, FpPoint) {
    let p = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37");
    let n = h("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D");
    let curve = Arc::new(FpCurve::new(p, i(0), i(3), Some(n), Some(i(1))));
    let g = curve.decode_point(&hb("04DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D")).unwrap();
    (curve, g)
}

/// SEC 2 **secp192r1** / NIST **P-192**（a=p−3, h=1）。
pub fn secp192r1() -> (Arc<FpCurve>, FpPoint) {
    let p = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
    let a = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC");
    let b = h("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");
    let n = h("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(i(1))));
    let g = curve.decode_point(&hb("04188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF101207192B95FFC8DA78631011ED6B24CDD573F977A11E794811")).unwrap();
    (curve, g)
}

/// SEC 2 **secp224k1** Koblitz 質數曲線（a=0, b=5, h=1）。
pub fn secp224k1() -> (Arc<FpCurve>, FpPoint) {
    let p = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D");
    let n = h("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7");
    let curve = Arc::new(FpCurve::new(p, i(0), i(5), Some(n), Some(i(1))));
    let g = curve.decode_point(&hb("04A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5")).unwrap();
    (curve, g)
}

/// SEC 2 **secp224r1** / NIST **P-224**（a=p−3, h=1）。
pub fn secp224r1() -> (Arc<FpCurve>, FpPoint) {
    let p = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
    let a = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");
    let b = h("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
    let n = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(i(1))));
    let g = curve.decode_point(&hb("04B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34")).unwrap();
    (curve, g)
}

/// SEC 2 **secp384r1** / NIST **P-384**（a=p−3, h=1）。
pub fn secp384r1() -> (Arc<FpCurve>, FpPoint) {
    let p = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");
    let a = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC");
    let b = h("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF");
    let n = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(i(1))));
    let g = curve.decode_point(&hb("04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F")).unwrap();
    (curve, g)
}

/// SEC 2 **secp521r1** / NIST **P-521**（a=p−3, h=1；p = 2^521 − 1）。
pub fn secp521r1() -> (Arc<FpCurve>, FpPoint) {
    let p = h("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let a = h("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC");
    let b = h("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00");
    let n = h("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(i(1))));
    let g = curve.decode_point(&hb("0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650")).unwrap();
    (curve, g)
}

// --- 其餘 SEC 2 二元曲線 ---

/// SEC 2 **sect233k1** Koblitz（x²³³+x⁷⁴+1，a=0, b=1, h=4）。
pub fn sect233k1() -> (Arc<F2mCurve>, F2mPoint) {
    let n = h("8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF");
    let curve = Arc::new(F2mCurve::trinomial(233, 74, i(0), i(1), Some(n), Some(i(4))));
    let g = curve.decode_point(&hb("04017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD612601DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3")).unwrap();
    (curve, g)
}

/// SEC 2 **sect233r1**（x²³³+x⁷⁴+1，a=1, h=2）。
pub fn sect233r1() -> (Arc<F2mCurve>, F2mPoint) {
    let b = h("0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD");
    let n = h("01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7");
    let curve = Arc::new(F2mCurve::trinomial(233, 74, i(1), b, Some(n), Some(i(2))));
    let g = curve.decode_point(&hb("0400FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052")).unwrap();
    (curve, g)
}

/// SEC 2 **sect283k1** Koblitz（x²⁸³+x¹²+x⁷+x⁵+1，a=0, b=1, h=4）。
pub fn sect283k1() -> (Arc<F2mCurve>, F2mPoint) {
    let n = h("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61");
    let curve = Arc::new(F2mCurve::pentanomial(283, 5, 7, 12, i(0), i(1), Some(n), Some(i(4))));
    let g = curve.decode_point(&hb("040503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC245849283601CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259")).unwrap();
    (curve, g)
}

/// SEC 2 **sect283r1**（x²⁸³+x¹²+x⁷+x⁵+1，a=1, h=2）。
pub fn sect283r1() -> (Arc<F2mCurve>, F2mPoint) {
    let b = h("027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5");
    let n = h("03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307");
    let curve = Arc::new(F2mCurve::pentanomial(283, 5, 7, 12, i(1), b, Some(n), Some(i(2))));
    let g = curve.decode_point(&hb("0405F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B1205303676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4")).unwrap();
    (curve, g)
}

/// 16 進位字串 → BigInteger（模組內小工具，供各命名曲線共用）。
fn h(s: &str) -> BigInteger {
    BigInteger::from_str_radix(s, 16).unwrap()
}

/// 小整數 → BigInteger（a/b/cofactor 的短常數）。
fn i(v: u32) -> BigInteger {
    BigInteger::from_u32(v)
}

/// 16 進位字串 → 位元組（基點的 04||X||Y 編碼；長度須為偶數）。
fn hb(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len()).step_by(2).map(|k| u8::from_str_radix(&s[k..k + 2], 16).unwrap()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // 每條命名曲線都驗：基點非無窮遠、n·G=O（參數正確）、壓縮/未壓縮 encode→decode
    // round-trip（含 decompress）。decode_point 建基點時已驗在曲線上（a/b/G 一致）。
    #[test]
    fn all_fp_named_curves_verify() {
        let curves = [
            ("secp192k1", secp192k1(), 192),
            ("secp192r1", secp192r1(), 192),
            ("secp224k1", secp224k1(), 224),
            ("secp224r1", secp224r1(), 224),
            ("secp256k1", secp256k1(), 256),
            ("secp256r1", secp256r1(), 256),
            ("secp384r1", secp384r1(), 384),
            ("secp521r1", secp521r1(), 521),
        ];
        for (name, (c, g), bits) in curves {
            assert_eq!(c.field_size(), bits, "{name} field_size");
            assert!(!g.is_infinity(), "{name} G");
            assert!((&g * c.order().unwrap()).is_infinity(), "{name} n·G");
            assert_eq!(c.decode_point(&g.encode(true)).unwrap(), g, "{name} compressed");
            assert_eq!(c.decode_point(&g.encode(false)).unwrap(), g, "{name} uncompressed");
        }
    }

    #[test]
    fn all_f2m_named_curves_verify() {
        let curves = [
            ("sect163k1", sect163k1(), 163),
            ("sect233k1", sect233k1(), 233),
            ("sect233r1", sect233r1(), 233),
            ("sect283k1", sect283k1(), 283),
            ("sect283r1", sect283r1(), 283),
        ];
        for (name, (c, g), bits) in curves {
            assert_eq!(c.field_size(), bits, "{name} field_size");
            assert!(!g.is_infinity(), "{name} G");
            assert!((&g * c.order().unwrap()).is_infinity(), "{name} n·G");
            assert_eq!(c.decode_point(&g.encode(true)).unwrap(), g, "{name} compressed");
            assert_eq!(c.decode_point(&g.encode(false)).unwrap(), g, "{name} uncompressed");
        }
    }
}
