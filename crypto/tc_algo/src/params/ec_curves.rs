use std::sync::OnceLock;

use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_ec_core::Curve;
use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator, EcPrivateKey, EcPublicKey};
#[cfg(feature = "f2m-curve")]
use tc_f2m_curve::{F2mCtCurve, F2mCtPoint};
#[cfg(feature = "f2m-custom")]
use tc_f2m_custom::{
    SecT113FieldElement, SecT131FieldElement, SecT163FieldElement, SecT193FieldElement,
    SecT233FieldElement, SecT239FieldElement, SecT283FieldElement, SecT409FieldElement,
    SecT571FieldElement, SecTCtCurve, SecTCtPoint,
};
#[cfg(feature = "fp-curve")]
use tc_fp_curve::{FpCtCurve, FpCtPoint, FpField};
#[cfg(feature = "fp-custom")]
use tc_fp_custom::{
    SM2P256V1FieldElement, SecP128R1FieldElement, SecP160R1FieldElement, SecP160R2FieldElement,
    SecP192K1FieldElement, SecP192R1FieldElement, SecP224K1FieldElement, SecP224R1FieldElement,
    SecP256K1FieldElement, SecP256R1FieldElement, SecP384R1FieldElement, SecP521R1FieldElement,
    SecPCtCurve, SecPCtPoint,
};

use crate::{AlgoError, ErrorKind, Params};

// The named curves of the EC key pair generator: the names and OIDs of Bouncy Castle's
// ECNamedCurveTable, which joins those of X9.62, SEC, NIST, TeleTrusT, ANSSI, GOST and GM, and the
// curves of DSTU 4145, which it gives by OID alone. Each curve is built once, in constant time, the
// first time it is used, and the points of its keys borrow it, so that the keys are 'static params.
// A curve with a faster form of its own, in tc_fp_custom or tc_f2m_custom, takes that form; the
// others take the generic one of tc_fp_curve or tc_f2m_curve
// A new key pair, public then private
pub(crate) type KeyPairResult = Result<(Box<dyn Params>, Box<dyn Params>), AlgoError>;

pub(crate) struct NamedCurve {
    pub(crate) names: &'static [&'static str],
    pub(crate) oid: &'static str,
    pub(crate) generate: fn(&mut dyn CryptoRng) -> KeyPairResult,
}

// The curve that a name, in any case, or an OID gives
pub(crate) fn by_name(name: &str) -> Option<&'static NamedCurve> {
    CURVES
        .iter()
        .find(|curve| curve.names.iter().any(|n| n.eq_ignore_ascii_case(name)))
}

pub(crate) fn by_oid(oid: &Asn1Oid) -> Option<&'static NamedCurve> {
    CURVES.iter().find(|curve| {
        curve
            .oid
            .parse::<Asn1Oid>()
            .is_ok_and(|dotted| &dotted == oid)
    })
}

fn key_pair<C>(g: C::Point, rand: &mut dyn CryptoRng) -> KeyPairResult
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
    EcPublicKey<C>: Params,
    EcPrivateKey<C>: Params,
{
    let mut generator = EcKeyPairGenerator::<C, _>::new(rand);
    generator
        .init(&EcKeyGenerationParams::new(g))
        .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
    let (public, private) = generator
        .generate_key_pair()
        .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
    Ok((Box::new(public), Box::new(private)))
}

#[cfg(feature = "fp-curve")]
fn secp112r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::SECP112R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn secp112r2() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::SECP112R2;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-custom")]
fn secp128r1() -> SecPCtPoint<'static, SecP128R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP128R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP128R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-curve")]
fn secp128r2() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::SECP128R2;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-custom")]
fn secp160k1() -> SecPCtPoint<'static, SecP160R2FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP160R2FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP160K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-custom")]
fn secp160r1() -> SecPCtPoint<'static, SecP160R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP160R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP160R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-custom")]
fn secp160r2() -> SecPCtPoint<'static, SecP160R2FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP160R2FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP160R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-custom")]
fn secp192k1() -> SecPCtPoint<'static, SecP192K1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP192K1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP192K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-custom")]
fn secp192r1() -> SecPCtPoint<'static, SecP192R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP192R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP192R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-custom")]
fn secp224k1() -> SecPCtPoint<'static, SecP224K1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP224K1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP224K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-custom")]
fn secp224r1() -> SecPCtPoint<'static, SecP224R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP224R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP224R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-custom")]
fn secp256k1() -> SecPCtPoint<'static, SecP256K1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP256K1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP256K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-custom")]
fn secp256r1() -> SecPCtPoint<'static, SecP256R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP256R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP256R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-custom")]
fn secp384r1() -> SecPCtPoint<'static, SecP384R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP384R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP384R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-custom")]
fn secp521r1() -> SecPCtPoint<'static, SecP521R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP521R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP521R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect113r1() -> SecTCtPoint<'static, SecT113FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT113FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT113R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect113r2() -> SecTCtPoint<'static, SecT113FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT113FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT113R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect131r1() -> SecTCtPoint<'static, SecT131FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT131FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT131R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect131r2() -> SecTCtPoint<'static, SecT131FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT131FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT131R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect163k1() -> SecTCtPoint<'static, SecT163FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT163FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT163K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect163r1() -> SecTCtPoint<'static, SecT163FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT163FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT163R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect163r2() -> SecTCtPoint<'static, SecT163FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT163FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT163R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect193r1() -> SecTCtPoint<'static, SecT193FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT193FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT193R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect193r2() -> SecTCtPoint<'static, SecT193FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT193FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT193R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect233k1() -> SecTCtPoint<'static, SecT233FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT233FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT233K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect233r1() -> SecTCtPoint<'static, SecT233FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT233FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT233R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect239k1() -> SecTCtPoint<'static, SecT239FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT239FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT239K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect283k1() -> SecTCtPoint<'static, SecT283FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT283FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT283K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect283r1() -> SecTCtPoint<'static, SecT283FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT283FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT283R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect409k1() -> SecTCtPoint<'static, SecT409FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT409FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT409K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect409r1() -> SecTCtPoint<'static, SecT409FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT409FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT409R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect571k1() -> SecTCtPoint<'static, SecT571FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT571FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT571K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-custom")]
fn sect571r1() -> SecTCtPoint<'static, SecT571FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT571FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT571R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-curve")]
fn prime192v2() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::PRIME192V2;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn prime192v3() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::PRIME192V3;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn prime239v1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::PRIME239V1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn prime239v2() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::PRIME239V2;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn prime239v3() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::PRIME239V3;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "f2m-curve")]
fn c2pnb163v1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB163V1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2pnb163v2() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB163V2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2pnb163v3() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB163V3;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2pnb176w1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB176W1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2tnb191v1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB191V1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2tnb191v2() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB191V2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2tnb191v3() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB191V3;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2pnb208w1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB208W1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2tnb239v1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB239V1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2tnb239v2() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB239V2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2tnb239v3() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB239V3;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2pnb272w1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB272W1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2pnb304w1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB304W1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2tnb359v1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB359V1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2pnb368w1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB368W1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn c2tnb431r1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB431R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp160r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP160R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp160t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP160T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp192r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP192R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp192t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP192T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp224r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP224R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp224t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP224T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp256r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP256R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp256t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP256T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp320r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP320R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp320t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP320T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp384r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP384R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp384t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP384T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp512r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP512R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn brainpoolp512t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP512T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn frp256v1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::FRP256V1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn gostr3410_2001_cryptopro_a() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::GOSTR3410_2001_CRYPTOPRO_A;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn gostr3410_2001_cryptopro_b() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::GOSTR3410_2001_CRYPTOPRO_B;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn gostr3410_2001_cryptopro_c() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::GOSTR3410_2001_CRYPTOPRO_C;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn gostr3410_2001_cryptopro_xcha() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::GOSTR3410_2001_CRYPTOPRO_XCHA;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn gostr3410_2001_cryptopro_xchb() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::GOSTR3410_2001_CRYPTOPRO_XCHB;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn tc26_gost_3410_12_256_paramseta() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_256_PARAMSETA;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn tc26_gost_3410_12_256_paramsetb() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_256_PARAMSETB;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn tc26_gost_3410_12_256_paramsetc() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_256_PARAMSETC;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn tc26_gost_3410_12_256_paramsetd() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_256_PARAMSETD;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn tc26_gost_3410_12_512_paramseta() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_512_PARAMSETA;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn tc26_gost_3410_12_512_paramsetb() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_512_PARAMSETB;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn tc26_gost_3410_12_512_paramsetc() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_512_PARAMSETC;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn wapip192v1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::WAPIP192V1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "fp-curve")]
fn wapi192v1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::WAPI192V1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

#[cfg(feature = "f2m-curve")]
fn dstu4145_163() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_163;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn dstu4145_167() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_167;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn dstu4145_173() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_173;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn dstu4145_179() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_179;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn dstu4145_191() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_191;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn dstu4145_233() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_233;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn dstu4145_257() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_257;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn dstu4145_307() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_307;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn dstu4145_367() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_367;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(feature = "f2m-curve")]
fn dstu4145_431() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_431;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

pub(crate) const CURVES: &[NamedCurve] = &[
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["secp112r1"],
        oid: "1.3.132.0.6",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(secp112r1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["secp112r2"],
        oid: "1.3.132.0.7",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(secp112r2(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["secp128r1"],
        oid: "1.3.132.0.28",
        generate: |rand| key_pair::<&'static SecPCtCurve<SecP128R1FieldElement>>(secp128r1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["secp128r2"],
        oid: "1.3.132.0.29",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(secp128r2(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["secp160k1"],
        oid: "1.3.132.0.9",
        generate: |rand| key_pair::<&'static SecPCtCurve<SecP160R2FieldElement>>(secp160k1(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["secp160r1"],
        oid: "1.3.132.0.8",
        generate: |rand| key_pair::<&'static SecPCtCurve<SecP160R1FieldElement>>(secp160r1(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["secp160r2"],
        oid: "1.3.132.0.30",
        generate: |rand| key_pair::<&'static SecPCtCurve<SecP160R2FieldElement>>(secp160r2(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["secp192k1"],
        oid: "1.3.132.0.31",
        generate: |rand| key_pair::<&'static SecPCtCurve<SecP192K1FieldElement>>(secp192k1(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["secp192r1", "prime192v1", "P-192"],
        oid: "1.2.840.10045.3.1.1",
        generate: |rand| key_pair::<&'static SecPCtCurve<SecP192R1FieldElement>>(secp192r1(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["secp224k1"],
        oid: "1.3.132.0.32",
        generate: |rand| key_pair::<&'static SecPCtCurve<SecP224K1FieldElement>>(secp224k1(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["secp224r1", "P-224"],
        oid: "1.3.132.0.33",
        generate: |rand| key_pair::<&'static SecPCtCurve<SecP224R1FieldElement>>(secp224r1(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["secp256k1"],
        oid: "1.3.132.0.10",
        generate: |rand| key_pair::<&'static SecPCtCurve<SecP256K1FieldElement>>(secp256k1(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["secp256r1", "prime256v1", "P-256"],
        oid: "1.2.840.10045.3.1.7",
        generate: |rand| key_pair::<&'static SecPCtCurve<SecP256R1FieldElement>>(secp256r1(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["secp384r1", "P-384"],
        oid: "1.3.132.0.34",
        generate: |rand| key_pair::<&'static SecPCtCurve<SecP384R1FieldElement>>(secp384r1(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["secp521r1", "P-521"],
        oid: "1.3.132.0.35",
        generate: |rand| key_pair::<&'static SecPCtCurve<SecP521R1FieldElement>>(secp521r1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect113r1"],
        oid: "1.3.132.0.4",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT113FieldElement>>(sect113r1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect113r2"],
        oid: "1.3.132.0.5",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT113FieldElement>>(sect113r2(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect131r1"],
        oid: "1.3.132.0.22",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT131FieldElement>>(sect131r1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect131r2"],
        oid: "1.3.132.0.23",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT131FieldElement>>(sect131r2(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect163k1", "K-163"],
        oid: "1.3.132.0.1",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT163FieldElement>>(sect163k1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect163r1"],
        oid: "1.3.132.0.2",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT163FieldElement>>(sect163r1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect163r2", "B-163"],
        oid: "1.3.132.0.15",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT163FieldElement>>(sect163r2(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect193r1"],
        oid: "1.3.132.0.24",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT193FieldElement>>(sect193r1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect193r2"],
        oid: "1.3.132.0.25",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT193FieldElement>>(sect193r2(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect233k1", "K-233"],
        oid: "1.3.132.0.26",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT233FieldElement>>(sect233k1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect233r1", "B-233"],
        oid: "1.3.132.0.27",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT233FieldElement>>(sect233r1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect239k1"],
        oid: "1.3.132.0.3",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT239FieldElement>>(sect239k1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect283k1", "K-283"],
        oid: "1.3.132.0.16",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT283FieldElement>>(sect283k1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect283r1", "B-283"],
        oid: "1.3.132.0.17",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT283FieldElement>>(sect283r1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect409k1", "K-409"],
        oid: "1.3.132.0.36",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT409FieldElement>>(sect409k1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect409r1", "B-409"],
        oid: "1.3.132.0.37",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT409FieldElement>>(sect409r1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect571k1", "K-571"],
        oid: "1.3.132.0.38",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT571FieldElement>>(sect571k1(), rand),
    },
    #[cfg(feature = "f2m-custom")]
    NamedCurve {
        names: &["sect571r1", "B-571"],
        oid: "1.3.132.0.39",
        generate: |rand| key_pair::<&'static SecTCtCurve<SecT571FieldElement>>(sect571r1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["prime192v2"],
        oid: "1.2.840.10045.3.1.2",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(prime192v2(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["prime192v3"],
        oid: "1.2.840.10045.3.1.3",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(prime192v3(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["prime239v1"],
        oid: "1.2.840.10045.3.1.4",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(prime239v1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["prime239v2"],
        oid: "1.2.840.10045.3.1.5",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(prime239v2(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["prime239v3"],
        oid: "1.2.840.10045.3.1.6",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(prime239v3(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2pnb163v1"],
        oid: "1.2.840.10045.3.0.1",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2pnb163v1(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2pnb163v2"],
        oid: "1.2.840.10045.3.0.2",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2pnb163v2(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2pnb163v3"],
        oid: "1.2.840.10045.3.0.3",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2pnb163v3(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2pnb176w1"],
        oid: "1.2.840.10045.3.0.4",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2pnb176w1(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2tnb191v1"],
        oid: "1.2.840.10045.3.0.5",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2tnb191v1(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2tnb191v2"],
        oid: "1.2.840.10045.3.0.6",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2tnb191v2(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2tnb191v3"],
        oid: "1.2.840.10045.3.0.7",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2tnb191v3(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2pnb208w1"],
        oid: "1.2.840.10045.3.0.10",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2pnb208w1(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2tnb239v1"],
        oid: "1.2.840.10045.3.0.11",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2tnb239v1(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2tnb239v2"],
        oid: "1.2.840.10045.3.0.12",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2tnb239v2(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2tnb239v3"],
        oid: "1.2.840.10045.3.0.13",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2tnb239v3(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2pnb272w1"],
        oid: "1.2.840.10045.3.0.16",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2pnb272w1(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2pnb304w1"],
        oid: "1.2.840.10045.3.0.17",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2pnb304w1(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2tnb359v1"],
        oid: "1.2.840.10045.3.0.18",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2tnb359v1(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2pnb368w1"],
        oid: "1.2.840.10045.3.0.19",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2pnb368w1(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &["c2tnb431r1"],
        oid: "1.2.840.10045.3.0.20",
        generate: |rand| key_pair::<&'static F2mCtCurve>(c2tnb431r1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP160r1"],
        oid: "1.3.36.3.3.2.8.1.1.1",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp160r1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP160t1"],
        oid: "1.3.36.3.3.2.8.1.1.2",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp160t1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP192r1"],
        oid: "1.3.36.3.3.2.8.1.1.3",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp192r1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP192t1"],
        oid: "1.3.36.3.3.2.8.1.1.4",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp192t1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP224r1"],
        oid: "1.3.36.3.3.2.8.1.1.5",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp224r1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP224t1"],
        oid: "1.3.36.3.3.2.8.1.1.6",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp224t1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP256r1"],
        oid: "1.3.36.3.3.2.8.1.1.7",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp256r1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP256t1"],
        oid: "1.3.36.3.3.2.8.1.1.8",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp256t1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP320r1"],
        oid: "1.3.36.3.3.2.8.1.1.9",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp320r1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP320t1"],
        oid: "1.3.36.3.3.2.8.1.1.10",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp320t1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP384r1"],
        oid: "1.3.36.3.3.2.8.1.1.11",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp384r1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP384t1"],
        oid: "1.3.36.3.3.2.8.1.1.12",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp384t1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP512r1"],
        oid: "1.3.36.3.3.2.8.1.1.13",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp512r1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["brainpoolP512t1"],
        oid: "1.3.36.3.3.2.8.1.1.14",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(brainpoolp512t1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["FRP256v1"],
        oid: "1.2.250.1.223.101.256.1",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(frp256v1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["GostR3410-2001-CryptoPro-A"],
        oid: "1.2.643.2.2.35.1",
        generate: |rand| {
            key_pair::<&'static FpCtCurve<'static>>(gostr3410_2001_cryptopro_a(), rand)
        },
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["GostR3410-2001-CryptoPro-B"],
        oid: "1.2.643.2.2.35.2",
        generate: |rand| {
            key_pair::<&'static FpCtCurve<'static>>(gostr3410_2001_cryptopro_b(), rand)
        },
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["GostR3410-2001-CryptoPro-C"],
        oid: "1.2.643.2.2.35.3",
        generate: |rand| {
            key_pair::<&'static FpCtCurve<'static>>(gostr3410_2001_cryptopro_c(), rand)
        },
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["GostR3410-2001-CryptoPro-XchA"],
        oid: "1.2.643.2.2.36.0",
        generate: |rand| {
            key_pair::<&'static FpCtCurve<'static>>(gostr3410_2001_cryptopro_xcha(), rand)
        },
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["GostR3410-2001-CryptoPro-XchB"],
        oid: "1.2.643.2.2.36.1",
        generate: |rand| {
            key_pair::<&'static FpCtCurve<'static>>(gostr3410_2001_cryptopro_xchb(), rand)
        },
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["Tc26-Gost-3410-12-256-paramSetA"],
        oid: "1.2.643.7.1.2.1.1.1",
        generate: |rand| {
            key_pair::<&'static FpCtCurve<'static>>(tc26_gost_3410_12_256_paramseta(), rand)
        },
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["Tc26-Gost-3410-12-256-paramSetB"],
        oid: "1.2.643.7.1.2.1.1.2",
        generate: |rand| {
            key_pair::<&'static FpCtCurve<'static>>(tc26_gost_3410_12_256_paramsetb(), rand)
        },
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["Tc26-Gost-3410-12-256-paramSetC"],
        oid: "1.2.643.7.1.2.1.1.3",
        generate: |rand| {
            key_pair::<&'static FpCtCurve<'static>>(tc26_gost_3410_12_256_paramsetc(), rand)
        },
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["Tc26-Gost-3410-12-256-paramSetD"],
        oid: "1.2.643.7.1.2.1.1.4",
        generate: |rand| {
            key_pair::<&'static FpCtCurve<'static>>(tc26_gost_3410_12_256_paramsetd(), rand)
        },
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["Tc26-Gost-3410-12-512-paramSetA"],
        oid: "1.2.643.7.1.2.1.2.1",
        generate: |rand| {
            key_pair::<&'static FpCtCurve<'static>>(tc26_gost_3410_12_512_paramseta(), rand)
        },
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["Tc26-Gost-3410-12-512-paramSetB"],
        oid: "1.2.643.7.1.2.1.2.2",
        generate: |rand| {
            key_pair::<&'static FpCtCurve<'static>>(tc26_gost_3410_12_512_paramsetb(), rand)
        },
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["Tc26-Gost-3410-12-512-paramSetC"],
        oid: "1.2.643.7.1.2.1.2.3",
        generate: |rand| {
            key_pair::<&'static FpCtCurve<'static>>(tc26_gost_3410_12_512_paramsetc(), rand)
        },
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["wapip192v1"],
        oid: "1.2.156.10197.1.301.101",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(wapip192v1(), rand),
    },
    #[cfg(feature = "fp-curve")]
    NamedCurve {
        names: &["wapi192v1"],
        oid: "1.2.156.11235.1.1.1",
        generate: |rand| key_pair::<&'static FpCtCurve<'static>>(wapi192v1(), rand),
    },
    #[cfg(feature = "fp-custom")]
    NamedCurve {
        names: &["sm2p256v1"],
        oid: "1.2.156.10197.1.301",
        generate: |rand| {
            key_pair::<&'static SecPCtCurve<SM2P256V1FieldElement>>(
                crate::params::sm2_keys::sm2p256v1(),
                rand,
            )
        },
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &[],
        oid: "1.2.804.2.1.1.1.1.3.1.1.2.0",
        generate: |rand| key_pair::<&'static F2mCtCurve>(dstu4145_163(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &[],
        oid: "1.2.804.2.1.1.1.1.3.1.1.2.1",
        generate: |rand| key_pair::<&'static F2mCtCurve>(dstu4145_167(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &[],
        oid: "1.2.804.2.1.1.1.1.3.1.1.2.2",
        generate: |rand| key_pair::<&'static F2mCtCurve>(dstu4145_173(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &[],
        oid: "1.2.804.2.1.1.1.1.3.1.1.2.3",
        generate: |rand| key_pair::<&'static F2mCtCurve>(dstu4145_179(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &[],
        oid: "1.2.804.2.1.1.1.1.3.1.1.2.4",
        generate: |rand| key_pair::<&'static F2mCtCurve>(dstu4145_191(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &[],
        oid: "1.2.804.2.1.1.1.1.3.1.1.2.5",
        generate: |rand| key_pair::<&'static F2mCtCurve>(dstu4145_233(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &[],
        oid: "1.2.804.2.1.1.1.1.3.1.1.2.6",
        generate: |rand| key_pair::<&'static F2mCtCurve>(dstu4145_257(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &[],
        oid: "1.2.804.2.1.1.1.1.3.1.1.2.7",
        generate: |rand| key_pair::<&'static F2mCtCurve>(dstu4145_307(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &[],
        oid: "1.2.804.2.1.1.1.1.3.1.1.2.8",
        generate: |rand| key_pair::<&'static F2mCtCurve>(dstu4145_367(), rand),
    },
    #[cfg(feature = "f2m-curve")]
    NamedCurve {
        names: &[],
        oid: "1.2.804.2.1.1.1.1.3.1.1.2.9",
        generate: |rand| key_pair::<&'static F2mCtCurve>(dstu4145_431(), rand),
    },
];

// The curve types that take EC keys: the generic ones of tc_fp_curve and tc_f2m_curve, which hold
// any prime or binary curve, and the special ones of tc_fp_custom and tc_f2m_custom, those of the
// keys of the EC key pair generator. It gives `$on::<C>` for each of them
#[allow(
    unused_macros,
    reason = "unused when ec is on without a signer, agreement or ECIES"
)]
macro_rules! ct_curves {
    ($on:ident) => {
        &[
            #[cfg(feature = "fp-curve")]
            $on::<&'static ::tc_fp_curve::FpCtCurve<'static>>,
            #[cfg(feature = "f2m-curve")]
            $on::<&'static ::tc_f2m_curve::F2mCtCurve>,
            #[cfg(feature = "fp-custom")]
            $on::<&'static ::tc_fp_custom::SecPCtCurve<::tc_fp_custom::SecP128R1FieldElement>>,
            #[cfg(feature = "fp-custom")]
            $on::<&'static ::tc_fp_custom::SecPCtCurve<::tc_fp_custom::SecP160R1FieldElement>>,
            #[cfg(feature = "fp-custom")]
            $on::<&'static ::tc_fp_custom::SecPCtCurve<::tc_fp_custom::SecP160R2FieldElement>>,
            #[cfg(feature = "fp-custom")]
            $on::<&'static ::tc_fp_custom::SecPCtCurve<::tc_fp_custom::SecP192K1FieldElement>>,
            #[cfg(feature = "fp-custom")]
            $on::<&'static ::tc_fp_custom::SecPCtCurve<::tc_fp_custom::SecP192R1FieldElement>>,
            #[cfg(feature = "fp-custom")]
            $on::<&'static ::tc_fp_custom::SecPCtCurve<::tc_fp_custom::SecP224K1FieldElement>>,
            #[cfg(feature = "fp-custom")]
            $on::<&'static ::tc_fp_custom::SecPCtCurve<::tc_fp_custom::SecP224R1FieldElement>>,
            #[cfg(feature = "fp-custom")]
            $on::<&'static ::tc_fp_custom::SecPCtCurve<::tc_fp_custom::SecP256K1FieldElement>>,
            #[cfg(feature = "fp-custom")]
            $on::<&'static ::tc_fp_custom::SecPCtCurve<::tc_fp_custom::SecP256R1FieldElement>>,
            #[cfg(feature = "fp-custom")]
            $on::<&'static ::tc_fp_custom::SecPCtCurve<::tc_fp_custom::SecP384R1FieldElement>>,
            #[cfg(feature = "fp-custom")]
            $on::<&'static ::tc_fp_custom::SecPCtCurve<::tc_fp_custom::SecP521R1FieldElement>>,
            #[cfg(feature = "fp-custom")]
            $on::<&'static ::tc_fp_custom::SecPCtCurve<::tc_fp_custom::SM2P256V1FieldElement>>,
            #[cfg(feature = "f2m-custom")]
            $on::<&'static ::tc_f2m_custom::SecTCtCurve<::tc_f2m_custom::SecT113FieldElement>>,
            #[cfg(feature = "f2m-custom")]
            $on::<&'static ::tc_f2m_custom::SecTCtCurve<::tc_f2m_custom::SecT131FieldElement>>,
            #[cfg(feature = "f2m-custom")]
            $on::<&'static ::tc_f2m_custom::SecTCtCurve<::tc_f2m_custom::SecT163FieldElement>>,
            #[cfg(feature = "f2m-custom")]
            $on::<&'static ::tc_f2m_custom::SecTCtCurve<::tc_f2m_custom::SecT193FieldElement>>,
            #[cfg(feature = "f2m-custom")]
            $on::<&'static ::tc_f2m_custom::SecTCtCurve<::tc_f2m_custom::SecT233FieldElement>>,
            #[cfg(feature = "f2m-custom")]
            $on::<&'static ::tc_f2m_custom::SecTCtCurve<::tc_f2m_custom::SecT239FieldElement>>,
            #[cfg(feature = "f2m-custom")]
            $on::<&'static ::tc_f2m_custom::SecTCtCurve<::tc_f2m_custom::SecT283FieldElement>>,
            #[cfg(feature = "f2m-custom")]
            $on::<&'static ::tc_f2m_custom::SecTCtCurve<::tc_f2m_custom::SecT409FieldElement>>,
            #[cfg(feature = "f2m-custom")]
            $on::<&'static ::tc_f2m_custom::SecTCtCurve<::tc_f2m_custom::SecT571FieldElement>>,
        ]
    };
}
#[allow(
    unused_imports,
    reason = "unused when ec is on without a signer, agreement or ECIES"
)]
pub(crate) use ct_curves;
