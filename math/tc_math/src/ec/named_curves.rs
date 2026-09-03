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
    let curve = Arc::new(FpCurve::new(
        p,
        a,
        b,
        Some(n),
        Some(BigInteger::from_u32(1)),
    ));
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
    let p = h(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
    );
    let a = h(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
    );
    let b = h(
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
    );
    let n = h(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
    );
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(i(1))));
    let g = curve.decode_point(&hb("04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F")).unwrap();
    (curve, g)
}

/// SEC 2 **secp521r1** / NIST **P-521**（a=p−3, h=1；p = 2^521 − 1）。
pub fn secp521r1() -> (Arc<FpCurve>, FpPoint) {
    let p = h(
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    );
    let a = h(
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
    );
    let b = h(
        "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
    );
    let n = h(
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
    );
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(i(1))));
    let g = curve.decode_point(&hb("0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650")).unwrap();
    (curve, g)
}

// --- 其餘 SEC 2 二元曲線 ---

/// SEC 2 **sect233k1** Koblitz（x²³³+x⁷⁴+1，a=0, b=1, h=4）。
pub fn sect233k1() -> (Arc<F2mCurve>, F2mPoint) {
    let n = h("8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF");
    let curve = Arc::new(F2mCurve::trinomial(
        233,
        74,
        i(0),
        i(1),
        Some(n),
        Some(i(4)),
    ));
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
    let curve = Arc::new(F2mCurve::pentanomial(
        283,
        5,
        7,
        12,
        i(0),
        i(1),
        Some(n),
        Some(i(4)),
    ));
    let g = curve.decode_point(&hb("040503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC245849283601CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259")).unwrap();
    (curve, g)
}

/// SEC 2 **sect283r1**（x²⁸³+x¹²+x⁷+x⁵+1，a=1, h=2）。
pub fn sect283r1() -> (Arc<F2mCurve>, F2mPoint) {
    let b = h("027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5");
    let n = h("03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307");
    let curve = Arc::new(F2mCurve::pentanomial(
        283,
        5,
        7,
        12,
        i(1),
        b,
        Some(n),
        Some(i(2)),
    ));
    let g = curve.decode_point(&hb("0405F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B1205303676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4")).unwrap();
    (curve, g)
}

// --- 已淘汰的弱質數曲線（< 96-bit 安全強度；僅為完整對照 bc / 舊資料互通保留）---

/// **Obsolete** SEC 2 secp112r1（~56-bit 安全）。
#[deprecated(note = "cryptographically weak (~56-bit); interop/completeness only")]
pub fn secp112r1() -> (Arc<FpCurve>, FpPoint) {
    let p = h("DB7C2ABF62E35E668076BEAD208B");
    let a = h("DB7C2ABF62E35E668076BEAD2088");
    let b = h("659EF8BA043916EEDE8911702B22");
    let n = h("DB7C2ABF62E35E7628DFAC6561C5");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(i(1))));
    let g = curve
        .decode_point(&hb(
            "0409487239995A5EE76B55F9C2F098A89CE5AF8724C0A23E0E0FF77500",
        ))
        .unwrap();
    (curve, g)
}

/// **Obsolete** SEC 2 secp112r2（~56-bit，h=4）。
#[deprecated(note = "cryptographically weak (~56-bit); interop/completeness only")]
pub fn secp112r2() -> (Arc<FpCurve>, FpPoint) {
    let p = h("DB7C2ABF62E35E668076BEAD208B");
    let a = h("6127C24C05F38A0AAAF65C0EF02C");
    let b = h("51DEF1815DB5ED74FCC34C85D709");
    let n = h("36DF0AAFD8B8D7597CA10520D04B");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(i(4))));
    let g = curve
        .decode_point(&hb(
            "044BA30AB5E892B4E1649DD0928643ADCD46F5882E3747DEF36E956E97",
        ))
        .unwrap();
    (curve, g)
}

/// **Obsolete** SEC 2 secp128r1（~64-bit）。
#[deprecated(note = "cryptographically weak (~64-bit); interop/completeness only")]
pub fn secp128r1() -> (Arc<FpCurve>, FpPoint) {
    let p = h("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
    let a = h("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC");
    let b = h("E87579C11079F43DD824993C2CEE5ED3");
    let n = h("FFFFFFFE0000000075A30D1B9038A115");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(i(1))));
    let g = curve
        .decode_point(&hb(
            "04161FF7528B899B2D0C28607CA52C5B86CF5AC8395BAFEB13C02DA292DDED7A83",
        ))
        .unwrap();
    (curve, g)
}

/// **Obsolete** SEC 2 secp128r2（~64-bit，h=4）。
#[deprecated(note = "cryptographically weak (~64-bit); interop/completeness only")]
pub fn secp128r2() -> (Arc<FpCurve>, FpPoint) {
    let p = h("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
    let a = h("D6031998D1B3BBFEBF59CC9BBFF9AEE1");
    let b = h("5EEEFCA380D02919DC2C6558BB6D8A5D");
    let n = h("3FFFFFFF7FFFFFFFBE0024720613B5A3");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(i(4))));
    let g = curve
        .decode_point(&hb(
            "047B6AA5D85E572983E6FB32A7CDEBC14027B6916A894D3AEE7106FE805FC34B44",
        ))
        .unwrap();
    (curve, g)
}

/// **Obsolete** SEC 2 secp160k1 Koblitz（~80-bit）。
#[deprecated(note = "cryptographically weak (~80-bit); interop/completeness only")]
pub fn secp160k1() -> (Arc<FpCurve>, FpPoint) {
    let p = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
    let n = h("0100000000000000000001B8FA16DFAB9ACA16B6B3");
    let curve = Arc::new(FpCurve::new(p, i(0), i(7), Some(n), Some(i(1))));
    let g = curve
        .decode_point(&hb(
            "043B4C382CE37AA192A4019E763036F4F5DD4D7EBB938CF935318FDCED6BC28286531733C3F03C4FEE",
        ))
        .unwrap();
    (curve, g)
}

/// **Obsolete** SEC 2 secp160r1（~80-bit）。
#[deprecated(note = "cryptographically weak (~80-bit); interop/completeness only")]
pub fn secp160r1() -> (Arc<FpCurve>, FpPoint) {
    let p = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF");
    let a = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC");
    let b = h("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45");
    let n = h("0100000000000000000001F4C8F927AED3CA752257");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(i(1))));
    let g = curve
        .decode_point(&hb(
            "044A96B5688EF573284664698968C38BB913CBFC8223A628553168947D59DCC912042351377AC5FB32",
        ))
        .unwrap();
    (curve, g)
}

/// **Obsolete** SEC 2 secp160r2（~80-bit）。
#[deprecated(note = "cryptographically weak (~80-bit); interop/completeness only")]
pub fn secp160r2() -> (Arc<FpCurve>, FpPoint) {
    let p = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
    let a = h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70");
    let b = h("B4E134D3FB59EB8BAB57274904664D5AF50388BA");
    let n = h("0100000000000000000000351EE786A818F3A1A16B");
    let curve = Arc::new(FpCurve::new(p, a, b, Some(n), Some(i(1))));
    let g = curve
        .decode_point(&hb(
            "0452DCB034293A117E1F4FF11B30F7199D3144CE6DFEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E",
        ))
        .unwrap();
    (curve, g)
}

// --- 已淘汰的弱二元曲線 ---

/// **Obsolete** SEC 2 sect113r1（x¹¹³+x⁹+1，~56-bit）。
#[deprecated(note = "cryptographically weak (~56-bit); interop/completeness only")]
pub fn sect113r1() -> (Arc<F2mCurve>, F2mPoint) {
    let a = h("003088250CA6E7C7FE649CE85820F7");
    let b = h("00E8BEE4D3E2260744188BE0E9C723");
    let n = h("0100000000000000D9CCEC8A39E56F");
    let curve = Arc::new(F2mCurve::trinomial(113, 9, a, b, Some(n), Some(i(2))));
    let g = curve
        .decode_point(&hb(
            "04009D73616F35F4AB1407D73562C10F00A52830277958EE84D1315ED31886",
        ))
        .unwrap();
    (curve, g)
}

/// **Obsolete** SEC 2 sect113r2（x¹¹³+x⁹+1，~56-bit）。
#[deprecated(note = "cryptographically weak (~56-bit); interop/completeness only")]
pub fn sect113r2() -> (Arc<F2mCurve>, F2mPoint) {
    let a = h("00689918DBEC7E5A0DD6DFC0AA55C7");
    let b = h("0095E9A9EC9B297BD4BF36E059184F");
    let n = h("010000000000000108789B2496AF93");
    let curve = Arc::new(F2mCurve::trinomial(113, 9, a, b, Some(n), Some(i(2))));
    let g = curve
        .decode_point(&hb(
            "0401A57A6A7B26CA5EF52FCDB816479700B3ADC94ED1FE674C06E695BABA1D",
        ))
        .unwrap();
    (curve, g)
}

/// **Obsolete** SEC 2 sect131r1（x¹³¹+x⁸+x³+x²+1，~65-bit）。
#[deprecated(note = "cryptographically weak (~65-bit); interop/completeness only")]
pub fn sect131r1() -> (Arc<F2mCurve>, F2mPoint) {
    let a = h("07A11B09A76B562144418FF3FF8C2570B8");
    let b = h("0217C05610884B63B9C6C7291678F9D341");
    let n = h("0400000000000000023123953A9464B54D");
    let curve = Arc::new(F2mCurve::pentanomial(
        131,
        2,
        3,
        8,
        a,
        b,
        Some(n),
        Some(i(2)),
    ));
    let g = curve
        .decode_point(&hb(
            "040081BAF91FDF9833C40F9C181343638399078C6E7EA38C001F73C8134B1B4EF9E150",
        ))
        .unwrap();
    (curve, g)
}

/// **Obsolete** SEC 2 sect131r2（x¹³¹+x⁸+x³+x²+1，~65-bit）。
#[deprecated(note = "cryptographically weak (~65-bit); interop/completeness only")]
pub fn sect131r2() -> (Arc<F2mCurve>, F2mPoint) {
    let a = h("03E5A88919D7CAFCBF415F07C2176573B2");
    let b = h("04B8266A46C55657AC734CE38F018F2192");
    let n = h("0400000000000000016954A233049BA98F");
    let curve = Arc::new(F2mCurve::pentanomial(
        131,
        2,
        3,
        8,
        a,
        b,
        Some(n),
        Some(i(2)),
    ));
    let g = curve
        .decode_point(&hb(
            "040356DCD8F2F95031AD652D23951BB366A80648F06D867940A5366D9E265DE9EB240F",
        ))
        .unwrap();
    (curve, g)
}

// --- 其餘二元曲線（sect163 r 變體、193、239、409、571）---

/// SEC 2 sect163r1（x¹⁶³+x⁷+x⁶+x³+1）。
pub fn sect163r1() -> (Arc<F2mCurve>, F2mPoint) {
    let a = h("07B6882CAAEFA84F9554FF8428BD88E246D2782AE2");
    let b = h("0713612DCDDCB40AAB946BDA29CA91F73AF958AFD9");
    let n = h("03FFFFFFFFFFFFFFFFFFFF48AAB689C29CA710279B");
    let curve = Arc::new(F2mCurve::pentanomial(
        163,
        3,
        6,
        7,
        a,
        b,
        Some(n),
        Some(i(2)),
    ));
    let g = curve.decode_point(&hb("040369979697AB43897789566789567F787A7876A65400435EDB42EFAFB2989D51FEFCE3C80988F41FF883")).unwrap();
    (curve, g)
}

/// SEC 2 sect163r2（x¹⁶³+x⁷+x⁶+x³+1，a=1）。
pub fn sect163r2() -> (Arc<F2mCurve>, F2mPoint) {
    let b = h("020A601907B8C953CA1481EB10512F78744A3205FD");
    let n = h("040000000000000000000292FE77E70C12A4234C33");
    let curve = Arc::new(F2mCurve::pentanomial(
        163,
        3,
        6,
        7,
        i(1),
        b,
        Some(n),
        Some(i(2)),
    ));
    let g = curve.decode_point(&hb("0403F0EBA16286A2D57EA0991168D4994637E8343E3600D51FBC6C71A0094FA2CDD545B11C5C0C797324F1")).unwrap();
    (curve, g)
}

/// SEC 2 sect193r1（x¹⁹³+x¹⁵+1）。
pub fn sect193r1() -> (Arc<F2mCurve>, F2mPoint) {
    let a = h("0017858FEB7A98975169E171F77B4087DE098AC8A911DF7B01");
    let b = h("00FDFB49BFE6C3A89FACADAA7A1E5BBC7CC1C2E5D831478814");
    let n = h("01000000000000000000000000C7F34A778F443ACC920EBA49");
    let curve = Arc::new(F2mCurve::trinomial(193, 15, a, b, Some(n), Some(i(2))));
    let g = curve.decode_point(&hb("0401F481BC5F0FF84A74AD6CDF6FDEF4BF6179625372D8C0C5E10025E399F2903712CCF3EA9E3A1AD17FB0B3201B6AF7CE1B05")).unwrap();
    (curve, g)
}

/// SEC 2 sect193r2（x¹⁹³+x¹⁵+1）。
pub fn sect193r2() -> (Arc<F2mCurve>, F2mPoint) {
    let a = h("0163F35A5137C2CE3EA6ED8667190B0BC43ECD69977702709B");
    let b = h("00C9BB9E8927D4D64C377E2AB2856A5B16E3EFB7F61D4316AE");
    let n = h("010000000000000000000000015AAB561B005413CCD4EE99D5");
    let curve = Arc::new(F2mCurve::trinomial(193, 15, a, b, Some(n), Some(i(2))));
    let g = curve.decode_point(&hb("0400D9B67D192E0367C803F39E1A7E82CA14A651350AAE617E8F01CE94335607C304AC29E7DEFBD9CA01F596F927224CDECF6C")).unwrap();
    (curve, g)
}

/// SEC 2 sect239k1 Koblitz（x²³⁹+x¹⁵⁸+1，a=0, b=1, h=4）。
pub fn sect239k1() -> (Arc<F2mCurve>, F2mPoint) {
    let n = h("2000000000000000000000000000005A79FEC67CB6E91F1C1DA800E478A5");
    let curve = Arc::new(F2mCurve::trinomial(
        239,
        158,
        i(0),
        i(1),
        Some(n),
        Some(i(4)),
    ));
    let g = curve.decode_point(&hb("0429A0B6A887A983E9730988A68727A8B2D126C44CC2CC7B2A6555193035DC76310804F12E549BDB011C103089E73510ACB275FC312A5DC6B76553F0CA")).unwrap();
    (curve, g)
}

/// SEC 2 sect409k1 Koblitz（x⁴⁰⁹+x⁸⁷+1，a=0, b=1, h=4）。
pub fn sect409k1() -> (Arc<F2mCurve>, F2mPoint) {
    let n = h(
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF",
    );
    let curve = Arc::new(F2mCurve::trinomial(
        409,
        87,
        i(0),
        i(1),
        Some(n),
        Some(i(4)),
    ));
    let g = curve.decode_point(&hb("040060F05F658F49C1AD3AB1890F7184210EFD0987E307C84C27ACCFB8F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE902374601E369050B7C4E42ACBA1DACBF04299C3460782F918EA427E6325165E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B")).unwrap();
    (curve, g)
}

/// SEC 2 sect409r1（x⁴⁰⁹+x⁸⁷+1，a=1, h=2）。
pub fn sect409r1() -> (Arc<F2mCurve>, F2mPoint) {
    let b = h(
        "0021A5C2C8EE9FEB5C4B9A753B7B476B7FD6422EF1F3DD674761FA99D6AC27C8A9A197B272822F6CD57A55AA4F50AE317B13545F",
    );
    let n = h(
        "010000000000000000000000000000000000000000000000000001E2AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173",
    );
    let curve = Arc::new(F2mCurve::trinomial(409, 87, i(1), b, Some(n), Some(i(2))));
    let g = curve.decode_point(&hb("04015D4860D088DDB3496B0C6064756260441CDE4AF1771D4DB01FFE5B34E59703DC255A868A1180515603AEAB60794E54BB7996A70061B1CFAB6BE5F32BBFA78324ED106A7636B9C5A7BD198D0158AA4F5488D08F38514F1FDF4B4F40D2181B3681C364BA0273C706")).unwrap();
    (curve, g)
}

/// SEC 2 sect571k1 Koblitz（x⁵⁷¹+x¹⁰+x⁵+x²+1，a=0, b=1, h=4）。
pub fn sect571k1() -> (Arc<F2mCurve>, F2mPoint) {
    let n = h(
        "020000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001",
    );
    let curve = Arc::new(F2mCurve::pentanomial(
        571,
        2,
        5,
        10,
        i(0),
        i(1),
        Some(n),
        Some(i(4)),
    ));
    let g = curve.decode_point(&hb("04026EB7A859923FBC82189631F8103FE4AC9CA2970012D5D46024804801841CA44370958493B205E647DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C89720349DC807F4FBF374F4AEADE3BCA95314DD58CEC9F307A54FFC61EFC006D8A2C9D4979C0AC44AEA74FBEBBB9F772AEDCB620B01A7BA7AF1B320430C8591984F601CD4C143EF1C7A3")).unwrap();
    (curve, g)
}

/// SEC 2 sect571r1（x⁵⁷¹+x¹⁰+x⁵+x²+1，a=1, h=2）。
pub fn sect571r1() -> (Arc<F2mCurve>, F2mPoint) {
    let b = h(
        "02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A",
    );
    let n = h(
        "03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47",
    );
    let curve = Arc::new(F2mCurve::pentanomial(
        571,
        2,
        5,
        10,
        i(1),
        b,
        Some(n),
        Some(i(2)),
    ));
    let g = curve.decode_point(&hb("040303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19037BF27342DA639B6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43BAB08A576291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B")).unwrap();
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
    (0..s.len())
        .step_by(2)
        .map(|k| u8::from_str_radix(&s[k..k + 2], 16).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // routine 驗證（快）：field_size + 基點壓縮/未壓縮 decode round-trip。decode 建基點
    // 已驗在曲線上（a/b/G 一致）。昂貴的 n·G=O 移到下面 #[ignore] 的測試。
    #[allow(deprecated)] // 涵蓋已淘汰的弱曲線
    #[test]
    fn all_fp_named_curves_verify() {
        let curves = [
            ("secp112r1", secp112r1(), 112),
            ("secp112r2", secp112r2(), 112),
            ("secp128r1", secp128r1(), 128),
            ("secp128r2", secp128r2(), 128),
            ("secp160k1", secp160k1(), 160),
            ("secp160r1", secp160r1(), 160),
            ("secp160r2", secp160r2(), 160),
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
            assert_eq!(
                c.decode_point(&g.encode(true)).unwrap(),
                g,
                "{name} compressed"
            );
            assert_eq!(
                c.decode_point(&g.encode(false)).unwrap(),
                g,
                "{name} uncompressed"
            );
        }
    }

    #[allow(deprecated)]
    #[test]
    fn all_f2m_named_curves_verify() {
        let curves = [
            ("sect113r1", sect113r1(), 113),
            ("sect113r2", sect113r2(), 113),
            ("sect131r1", sect131r1(), 131),
            ("sect131r2", sect131r2(), 131),
            ("sect163k1", sect163k1(), 163),
            ("sect163r1", sect163r1(), 163),
            ("sect163r2", sect163r2(), 163),
            ("sect193r1", sect193r1(), 193),
            ("sect193r2", sect193r2(), 193),
            ("sect233k1", sect233k1(), 233),
            ("sect233r1", sect233r1(), 233),
            ("sect239k1", sect239k1(), 239),
            ("sect283k1", sect283k1(), 283),
            ("sect283r1", sect283r1(), 283),
            ("sect409k1", sect409k1(), 409),
            ("sect409r1", sect409r1(), 409),
            ("sect571k1", sect571k1(), 571),
            ("sect571r1", sect571r1(), 571),
        ];
        for (name, (c, g), bits) in curves {
            assert_eq!(c.field_size(), bits, "{name} field_size");
            assert!(!g.is_infinity(), "{name} G");
            assert_eq!(
                c.decode_point(&g.encode(true)).unwrap(),
                g,
                "{name} compressed"
            );
            assert_eq!(
                c.decode_point(&g.encode(false)).unwrap(),
                g,
                "{name} uncompressed"
            );
        }
    }

    // 完整 n·G=O（驗群階 n 與純量乘全路徑）。affine 變動時間 + 大體域反元素很慢
    // （sect571 尤甚），故標 #[ignore]；跑：`cargo test -- --ignored`（建議 --release）。
    #[allow(deprecated)]
    #[test]
    #[ignore = "slow: full n·G=O over all curves incl. sect571"]
    fn all_named_curves_n_times_g_is_infinity() {
        let fp = [
            secp112r1(),
            secp112r2(),
            secp128r1(),
            secp128r2(),
            secp160k1(),
            secp160r1(),
            secp160r2(),
            secp192k1(),
            secp192r1(),
            secp224k1(),
            secp224r1(),
            secp256k1(),
            secp256r1(),
            secp384r1(),
            secp521r1(),
        ];
        for (c, g) in fp {
            assert!((&g * c.order().unwrap()).is_infinity());
        }
        let f2m = [
            sect113r1(),
            sect113r2(),
            sect131r1(),
            sect131r2(),
            sect163k1(),
            sect163r1(),
            sect163r2(),
            sect193r1(),
            sect193r2(),
            sect233k1(),
            sect233r1(),
            sect239k1(),
            sect283k1(),
            sect283r1(),
            sect409k1(),
            sect409r1(),
            sect571k1(),
            sect571r1(),
        ];
        for (c, g) in f2m {
            assert!((&g * c.order().unwrap()).is_infinity());
        }
    }
}
