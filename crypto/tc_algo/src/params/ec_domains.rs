// The curve type each EC key is generic over, one per named curve. Each is a reference to a
// curve that lives for the whole program, so the keys are 'static

#[cfg(feature = "ec-small-curves")]
pub(super) type Secp112r1 = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(feature = "ec-small-curves")]
pub(super) type Secp112r2 = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(feature = "ec-small-curves")]
pub(super) type Secp128r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP128R1FieldElement>;

#[cfg(feature = "ec-small-curves")]
pub(super) type Secp128r2 = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(feature = "ec-small-curves")]
pub(super) type Secp160k1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP160R2FieldElement>;

#[cfg(feature = "ec-small-curves")]
pub(super) type Secp160r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP160R1FieldElement>;

#[cfg(feature = "ec-small-curves")]
pub(super) type Secp160r2 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP160R2FieldElement>;

#[cfg(feature = "ec-small-curves")]
pub(super) type Secp192k1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP192K1FieldElement>;

#[cfg(feature = "ec-small-curves")]
pub(super) type Secp192r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP192R1FieldElement>;

pub(super) type Secp224k1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP224K1FieldElement>;

pub(super) type Secp224r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP224R1FieldElement>;

pub(super) type Secp256k1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP256K1FieldElement>;

pub(super) type Secp256r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP256R1FieldElement>;

pub(super) type Secp384r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP384R1FieldElement>;

pub(super) type Secp521r1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SecP521R1FieldElement>;

pub(super) type Sm2p256v1 = &'static tc_fp_custom::SecPCtCurve<tc_fp_custom::SM2P256V1FieldElement>;

#[cfg(feature = "ec-gost")]
pub(super) type GostCryptoProA = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(feature = "ec-gost")]
pub(super) type GostCryptoProB = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(feature = "ec-gost")]
pub(super) type GostCryptoProC = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(feature = "ec-gost")]
pub(super) type GostTc26ParamSet256A = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(feature = "ec-gost")]
pub(super) type GostTc26ParamSet512A = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(feature = "ec-gost")]
pub(super) type GostTc26ParamSet512B = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(feature = "ec-gost")]
pub(super) type GostTc26ParamSet512C = &'static tc_fp_curve::FpCtCurve<'static>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(super) type Sect113r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT113FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(super) type Sect113r2 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT113FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(super) type Sect131r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT131FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(super) type Sect131r2 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT131FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(super) type Sect163k1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT163FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(super) type Sect163r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT163FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(super) type Sect163r2 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT163FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(super) type Sect193r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT193FieldElement>;

#[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
pub(super) type Sect193r2 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT193FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(super) type Sect233k1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT233FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(super) type Sect233r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT233FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(super) type Sect239k1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT239FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(super) type Sect283k1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT283FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(super) type Sect283r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT283FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(super) type Sect409k1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT409FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(super) type Sect409r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT409FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(super) type Sect571k1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT571FieldElement>;

#[cfg(feature = "ec-f2m")]
pub(super) type Sect571r1 = &'static tc_f2m_custom::SecTCtCurve<tc_f2m_custom::SecT571FieldElement>;
