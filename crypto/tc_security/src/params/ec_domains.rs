//! 每條曲線一個全域的常數時間曲線，第一次用到時建立；金鑰裡的點借用它，所以金鑰是 `'static`。

use std::sync::OnceLock;

#[cfg(feature = "ec-small-curves")]
pub(crate) type Secp112r1 = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(feature = "ec-small-curves")]
pub(crate) fn secp112r1() -> tc_fp_curve::FpCtPoint<'static> {
    static FIELD: OnceLock<tc_fp_curve::FpField> = OnceLock::new();
    static CURVE: OnceLock<tc_fp_curve::FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::SECP112R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "ec-small-curves")]
pub(crate) type Secp112r2 = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(feature = "ec-small-curves")]
pub(crate) fn secp112r2() -> tc_fp_curve::FpCtPoint<'static> {
    static FIELD: OnceLock<tc_fp_curve::FpField> = OnceLock::new();
    static CURVE: OnceLock<tc_fp_curve::FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::SECP112R2;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "ec-small-curves")]
pub(crate) type Secp128r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP128R1FieldElement>;

#[cfg(feature = "ec-small-curves")]
pub(crate) fn secp128r1() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SecP128R1FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP128R1FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP128R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-small-curves")]
pub(crate) type Secp128r2 = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(feature = "ec-small-curves")]
pub(crate) fn secp128r2() -> tc_fp_curve::FpCtPoint<'static> {
    static FIELD: OnceLock<tc_fp_curve::FpField> = OnceLock::new();
    static CURVE: OnceLock<tc_fp_curve::FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::SECP128R2;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "ec-small-curves")]
pub(crate) type Secp160k1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP160R2FieldElement>;

#[cfg(feature = "ec-small-curves")]
pub(crate) fn secp160k1() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SecP160R2FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP160R2FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP160K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-small-curves")]
pub(crate) type Secp160r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP160R1FieldElement>;

#[cfg(feature = "ec-small-curves")]
pub(crate) fn secp160r1() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SecP160R1FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP160R1FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP160R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-small-curves")]
pub(crate) type Secp160r2 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP160R2FieldElement>;

#[cfg(feature = "ec-small-curves")]
pub(crate) fn secp160r2() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SecP160R2FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP160R2FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP160R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-small-curves")]
pub(crate) type Secp192k1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP192K1FieldElement>;

#[cfg(feature = "ec-small-curves")]
pub(crate) fn secp192k1() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SecP192K1FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP192K1FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP192K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-small-curves")]
pub(crate) type Secp192r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP192R1FieldElement>;

#[cfg(feature = "ec-small-curves")]
pub(crate) fn secp192r1() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SecP192R1FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP192R1FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP192R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

pub(crate) type Secp224k1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP224K1FieldElement>;

pub(crate) fn secp224k1() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SecP224K1FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP224K1FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP224K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

pub(crate) type Secp224r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP224R1FieldElement>;

pub(crate) fn secp224r1() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SecP224R1FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP224R1FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP224R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

pub(crate) type Secp256k1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP256K1FieldElement>;

pub(crate) fn secp256k1() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SecP256K1FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP256K1FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP256K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

pub(crate) type Secp256r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP256R1FieldElement>;

pub(crate) fn secp256r1() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SecP256R1FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP256R1FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP256R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

pub(crate) type Secp384r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP384R1FieldElement>;

pub(crate) fn secp384r1() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SecP384R1FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP384R1FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP384R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

pub(crate) type Secp521r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP521R1FieldElement>;

pub(crate) fn secp521r1() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SecP521R1FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP521R1FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP521R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

pub(crate) type Sm2p256v1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SM2P256V1FieldElement>;

pub(crate) fn sm2p256v1() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::SM2P256V1FieldElement>
{
    static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::SM2P256V1FieldElement>> =
        OnceLock::new();
    let named = tc_fp_custom::named_curves::SM2P256V1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) type Sect113r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT113FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) fn sect113r1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT113FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT113FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT113R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) type Sect113r2 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT113FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) fn sect113r2() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT113FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT113FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT113R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) type Sect131r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT131FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) fn sect131r1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT131FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT131FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT131R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) type Sect131r2 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT131FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) fn sect131r2() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT131FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT131FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT131R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) type Sect163k1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT163FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) fn sect163k1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT163FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT163FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT163K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) type Sect163r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT163FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) fn sect163r1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT163FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT163FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT163R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) type Sect163r2 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT163FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) fn sect163r2() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT163FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT163FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT163R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) type Sect193r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT193FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) fn sect193r1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT193FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT193FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT193R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) type Sect193r2 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT193FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(crate) fn sect193r2() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT193FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT193FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT193R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-f2m")]
pub(crate) type Sect233k1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT233FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(crate) fn sect233k1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT233FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT233FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT233K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-f2m")]
pub(crate) type Sect233r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT233FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(crate) fn sect233r1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT233FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT233FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT233R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-f2m")]
pub(crate) type Sect239k1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT239FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(crate) fn sect239k1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT239FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT239FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT239K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-f2m")]
pub(crate) type Sect283k1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT283FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(crate) fn sect283k1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT283FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT283FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT283K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-f2m")]
pub(crate) type Sect283r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT283FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(crate) fn sect283r1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT283FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT283FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT283R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-f2m")]
pub(crate) type Sect409k1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT409FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(crate) fn sect409k1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT409FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT409FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT409K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-f2m")]
pub(crate) type Sect409r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT409FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(crate) fn sect409r1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT409FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT409FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT409R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-f2m")]
pub(crate) type Sect571k1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT571FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(crate) fn sect571k1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT571FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT571FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT571K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "ec-f2m")]
pub(crate) type Sect571r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT571FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(crate) fn sect571r1() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::SecT571FieldElement>
{
    static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT571FieldElement>> =
        OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT571R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}
