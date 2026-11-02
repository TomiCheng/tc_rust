// The generator G of each named curve, on a curve built once for the whole program, as the keys
// point into their curve. These are the curves of Bouncy Castle's ECNamedCurveTable that the
// features enable, each the Ct type of its key

use std::sync::OnceLock;

// A curve of tc_fp_custom
macro_rules! secp {
    ($(#[$cfg:meta])* $name:ident, $named:ident, $element:ident) => {
        $(#[$cfg])*
        pub(crate) fn $name() -> tc_fp_custom::SecPCtPoint<'static, tc_fp_custom::$element> {
            static CURVE: OnceLock<tc_fp_custom::SecPCtCurve<tc_fp_custom::$element>> =
                OnceLock::new();
            let named = tc_fp_custom::named_curves::$named;
            named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
        }
    };
}

// A small curve of tc_fp_curve, whose curve borrows its field
#[cfg(feature = "ec-small-curves")]
macro_rules! fp {
    ($name:ident, $named:ident) => {
        pub(crate) fn $name() -> tc_fp_curve::FpCtPoint<'static> {
            static FIELD: OnceLock<tc_fp_curve::FpField> = OnceLock::new();
            static CURVE: OnceLock<tc_fp_curve::FpCtCurve<'static>> = OnceLock::new();
            let named = tc_fp_curve::named_curves::$named;
            let field = FIELD.get_or_init(|| named.field());
            named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
        }
    };
}

// A binary curve of tc_f2m_custom
#[cfg(feature = "ec-f2m")]
macro_rules! sect {
    ($(#[$cfg:meta])* $name:ident, $named:ident, $element:ident) => {
        $(#[$cfg])*
        pub(crate) fn $name() -> tc_f2m_custom::SecTCtPoint<'static, tc_f2m_custom::$element> {
            static CURVE: OnceLock<tc_f2m_custom::SecTCtCurve<tc_f2m_custom::$element>> =
                OnceLock::new();
            let named = tc_f2m_custom::named_curves::$named;
            named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
        }
    };
}

#[cfg(feature = "ec-small-curves")]
fp!(secp112r1, SECP112R1);
#[cfg(feature = "ec-small-curves")]
fp!(secp112r2, SECP112R2);
secp!(#[cfg(feature = "ec-small-curves")] secp128r1, SECP128R1, SecP128R1FieldElement);
#[cfg(feature = "ec-small-curves")]
fp!(secp128r2, SECP128R2);
secp!(#[cfg(feature = "ec-small-curves")] secp160k1, SECP160K1, SecP160R2FieldElement);
secp!(#[cfg(feature = "ec-small-curves")] secp160r1, SECP160R1, SecP160R1FieldElement);
secp!(#[cfg(feature = "ec-small-curves")] secp160r2, SECP160R2, SecP160R2FieldElement);
secp!(#[cfg(feature = "ec-small-curves")] secp192k1, SECP192K1, SecP192K1FieldElement);
secp!(#[cfg(feature = "ec-small-curves")] secp192r1, SECP192R1, SecP192R1FieldElement);
secp!(secp224k1, SECP224K1, SecP224K1FieldElement);
secp!(secp224r1, SECP224R1, SecP224R1FieldElement);
secp!(secp256k1, SECP256K1, SecP256K1FieldElement);
secp!(secp256r1, SECP256R1, SecP256R1FieldElement);
secp!(secp384r1, SECP384R1, SecP384R1FieldElement);
secp!(secp521r1, SECP521R1, SecP521R1FieldElement);
secp!(sm2p256v1, SM2P256V1, SM2P256V1FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(#[cfg(feature = "ec-small-curves")] sect113r1, SECT113R1, SecT113FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(#[cfg(feature = "ec-small-curves")] sect113r2, SECT113R2, SecT113FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(#[cfg(feature = "ec-small-curves")] sect131r1, SECT131R1, SecT131FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(#[cfg(feature = "ec-small-curves")] sect131r2, SECT131R2, SecT131FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(#[cfg(feature = "ec-small-curves")] sect163k1, SECT163K1, SecT163FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(#[cfg(feature = "ec-small-curves")] sect163r1, SECT163R1, SecT163FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(#[cfg(feature = "ec-small-curves")] sect163r2, SECT163R2, SecT163FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(#[cfg(feature = "ec-small-curves")] sect193r1, SECT193R1, SecT193FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(#[cfg(feature = "ec-small-curves")] sect193r2, SECT193R2, SecT193FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(sect233k1, SECT233K1, SecT233FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(sect233r1, SECT233R1, SecT233FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(sect239k1, SECT239K1, SecT239FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(sect283k1, SECT283K1, SecT283FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(sect283r1, SECT283R1, SecT283FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(sect409k1, SECT409K1, SecT409FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(sect409r1, SECT409R1, SecT409FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(sect571k1, SECT571K1, SecT571FieldElement);
#[cfg(feature = "ec-f2m")]
sect!(sect571r1, SECT571R1, SecT571FieldElement);

// Calls the macro given with every curve whose feature is on, as `EcCurve variant => generator
// function of this module`, each behind its cfg. The macros that match on every curve take their
// list from here, so a new curve is added once
macro_rules! with_ec_curves {
    ($macro:ident) => {
        $macro! {
            #[cfg(feature = "ec-small-curves")] Secp112r1 => secp112r1,
            #[cfg(feature = "ec-small-curves")] Secp112r2 => secp112r2,
            #[cfg(feature = "ec-small-curves")] Secp128r1 => secp128r1,
            #[cfg(feature = "ec-small-curves")] Secp128r2 => secp128r2,
            #[cfg(feature = "ec-small-curves")] Secp160k1 => secp160k1,
            #[cfg(feature = "ec-small-curves")] Secp160r1 => secp160r1,
            #[cfg(feature = "ec-small-curves")] Secp160r2 => secp160r2,
            #[cfg(feature = "ec-small-curves")] Secp192k1 => secp192k1,
            #[cfg(feature = "ec-small-curves")] Secp192r1 => secp192r1,
            Secp224k1 => secp224k1,
            Secp224r1 => secp224r1,
            Secp256k1 => secp256k1,
            Secp256r1 => secp256r1,
            Secp384r1 => secp384r1,
            Secp521r1 => secp521r1,
            Sm2p256v1 => sm2p256v1,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))] Sect113r1 => sect113r1,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))] Sect113r2 => sect113r2,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))] Sect131r1 => sect131r1,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))] Sect131r2 => sect131r2,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))] Sect163k1 => sect163k1,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))] Sect163r1 => sect163r1,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))] Sect163r2 => sect163r2,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))] Sect193r1 => sect193r1,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))] Sect193r2 => sect193r2,
            #[cfg(feature = "ec-f2m")] Sect233k1 => sect233k1,
            #[cfg(feature = "ec-f2m")] Sect233r1 => sect233r1,
            #[cfg(feature = "ec-f2m")] Sect239k1 => sect239k1,
            #[cfg(feature = "ec-f2m")] Sect283k1 => sect283k1,
            #[cfg(feature = "ec-f2m")] Sect283r1 => sect283r1,
            #[cfg(feature = "ec-f2m")] Sect409k1 => sect409k1,
            #[cfg(feature = "ec-f2m")] Sect409r1 => sect409r1,
            #[cfg(feature = "ec-f2m")] Sect571k1 => sect571k1,
            #[cfg(feature = "ec-f2m")] Sect571r1 => sect571r1,
        }
    };
}

pub(crate) use with_ec_curves;
