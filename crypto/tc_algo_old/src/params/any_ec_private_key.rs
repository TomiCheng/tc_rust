use core::fmt;

use tc_ec_key::EcPrivateKey;

use super::EcCurve;
use super::ec_domains as domain;

// An EC private key, Bouncy Castle's `ECPrivateKeyParameters`, one variant per curve; d is wiped on drop. Each key is
// boxed: the curves differ a lot in size, so the enum holds only a pointer
#[derive(Clone)]
#[non_exhaustive]
pub enum AnyEcPrivateKey {
    #[cfg(feature = "ec-small-curves")]
    Secp112r1(Box<EcPrivateKey<domain::Secp112r1>>),
    #[cfg(feature = "ec-small-curves")]
    Secp112r2(Box<EcPrivateKey<domain::Secp112r2>>),
    #[cfg(feature = "ec-small-curves")]
    Secp128r1(Box<EcPrivateKey<domain::Secp128r1>>),
    #[cfg(feature = "ec-small-curves")]
    Secp128r2(Box<EcPrivateKey<domain::Secp128r2>>),
    #[cfg(feature = "ec-small-curves")]
    Secp160k1(Box<EcPrivateKey<domain::Secp160k1>>),
    #[cfg(feature = "ec-small-curves")]
    Secp160r1(Box<EcPrivateKey<domain::Secp160r1>>),
    #[cfg(feature = "ec-small-curves")]
    Secp160r2(Box<EcPrivateKey<domain::Secp160r2>>),
    #[cfg(feature = "ec-small-curves")]
    Secp192k1(Box<EcPrivateKey<domain::Secp192k1>>),
    #[cfg(feature = "ec-small-curves")]
    Secp192r1(Box<EcPrivateKey<domain::Secp192r1>>),
    Secp224k1(Box<EcPrivateKey<domain::Secp224k1>>),
    Secp224r1(Box<EcPrivateKey<domain::Secp224r1>>),
    Secp256k1(Box<EcPrivateKey<domain::Secp256k1>>),
    Secp256r1(Box<EcPrivateKey<domain::Secp256r1>>),
    Secp384r1(Box<EcPrivateKey<domain::Secp384r1>>),
    Secp521r1(Box<EcPrivateKey<domain::Secp521r1>>),
    Sm2p256v1(Box<EcPrivateKey<domain::Sm2p256v1>>),
    #[cfg(feature = "ec-gost")]
    GostCryptoProA(Box<EcPrivateKey<domain::GostCryptoProA>>),
    #[cfg(feature = "ec-gost")]
    GostCryptoProB(Box<EcPrivateKey<domain::GostCryptoProB>>),
    #[cfg(feature = "ec-gost")]
    GostCryptoProC(Box<EcPrivateKey<domain::GostCryptoProC>>),
    #[cfg(feature = "ec-gost")]
    GostTc26ParamSet256A(Box<EcPrivateKey<domain::GostTc26ParamSet256A>>),
    #[cfg(feature = "ec-gost")]
    GostTc26ParamSet512A(Box<EcPrivateKey<domain::GostTc26ParamSet512A>>),
    #[cfg(feature = "ec-gost")]
    GostTc26ParamSet512B(Box<EcPrivateKey<domain::GostTc26ParamSet512B>>),
    #[cfg(feature = "ec-gost")]
    GostTc26ParamSet512C(Box<EcPrivateKey<domain::GostTc26ParamSet512C>>),
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect113r1(Box<EcPrivateKey<domain::Sect113r1>>),
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect113r2(Box<EcPrivateKey<domain::Sect113r2>>),
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect131r1(Box<EcPrivateKey<domain::Sect131r1>>),
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect131r2(Box<EcPrivateKey<domain::Sect131r2>>),
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect163k1(Box<EcPrivateKey<domain::Sect163k1>>),
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect163r1(Box<EcPrivateKey<domain::Sect163r1>>),
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect163r2(Box<EcPrivateKey<domain::Sect163r2>>),
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect193r1(Box<EcPrivateKey<domain::Sect193r1>>),
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect193r2(Box<EcPrivateKey<domain::Sect193r2>>),
    #[cfg(feature = "ec-f2m")]
    Sect233k1(Box<EcPrivateKey<domain::Sect233k1>>),
    #[cfg(feature = "ec-f2m")]
    Sect233r1(Box<EcPrivateKey<domain::Sect233r1>>),
    #[cfg(feature = "ec-f2m")]
    Sect239k1(Box<EcPrivateKey<domain::Sect239k1>>),
    #[cfg(feature = "ec-f2m")]
    Sect283k1(Box<EcPrivateKey<domain::Sect283k1>>),
    #[cfg(feature = "ec-f2m")]
    Sect283r1(Box<EcPrivateKey<domain::Sect283r1>>),
    #[cfg(feature = "ec-f2m")]
    Sect409k1(Box<EcPrivateKey<domain::Sect409k1>>),
    #[cfg(feature = "ec-f2m")]
    Sect409r1(Box<EcPrivateKey<domain::Sect409r1>>),
    #[cfg(feature = "ec-f2m")]
    Sect571k1(Box<EcPrivateKey<domain::Sect571k1>>),
    #[cfg(feature = "ec-f2m")]
    Sect571r1(Box<EcPrivateKey<domain::Sect571r1>>),
}

impl AnyEcPrivateKey {
    // The curve the key is on
    pub fn curve(&self) -> EcCurve {
        match self {
            #[cfg(feature = "ec-small-curves")]
            Self::Secp112r1(_) => EcCurve::Secp112r1,
            #[cfg(feature = "ec-small-curves")]
            Self::Secp112r2(_) => EcCurve::Secp112r2,
            #[cfg(feature = "ec-small-curves")]
            Self::Secp128r1(_) => EcCurve::Secp128r1,
            #[cfg(feature = "ec-small-curves")]
            Self::Secp128r2(_) => EcCurve::Secp128r2,
            #[cfg(feature = "ec-small-curves")]
            Self::Secp160k1(_) => EcCurve::Secp160k1,
            #[cfg(feature = "ec-small-curves")]
            Self::Secp160r1(_) => EcCurve::Secp160r1,
            #[cfg(feature = "ec-small-curves")]
            Self::Secp160r2(_) => EcCurve::Secp160r2,
            #[cfg(feature = "ec-small-curves")]
            Self::Secp192k1(_) => EcCurve::Secp192k1,
            #[cfg(feature = "ec-small-curves")]
            Self::Secp192r1(_) => EcCurve::Secp192r1,
            Self::Secp224k1(_) => EcCurve::Secp224k1,
            Self::Secp224r1(_) => EcCurve::Secp224r1,
            Self::Secp256k1(_) => EcCurve::Secp256k1,
            Self::Secp256r1(_) => EcCurve::Secp256r1,
            Self::Secp384r1(_) => EcCurve::Secp384r1,
            Self::Secp521r1(_) => EcCurve::Secp521r1,
            Self::Sm2p256v1(_) => EcCurve::Sm2p256v1,
            #[cfg(feature = "ec-gost")]
            Self::GostCryptoProA(_) => EcCurve::GostCryptoProA,
            #[cfg(feature = "ec-gost")]
            Self::GostCryptoProB(_) => EcCurve::GostCryptoProB,
            #[cfg(feature = "ec-gost")]
            Self::GostCryptoProC(_) => EcCurve::GostCryptoProC,
            #[cfg(feature = "ec-gost")]
            Self::GostTc26ParamSet256A(_) => EcCurve::GostTc26ParamSet256A,
            #[cfg(feature = "ec-gost")]
            Self::GostTc26ParamSet512A(_) => EcCurve::GostTc26ParamSet512A,
            #[cfg(feature = "ec-gost")]
            Self::GostTc26ParamSet512B(_) => EcCurve::GostTc26ParamSet512B,
            #[cfg(feature = "ec-gost")]
            Self::GostTc26ParamSet512C(_) => EcCurve::GostTc26ParamSet512C,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
            Self::Sect113r1(_) => EcCurve::Sect113r1,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
            Self::Sect113r2(_) => EcCurve::Sect113r2,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
            Self::Sect131r1(_) => EcCurve::Sect131r1,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
            Self::Sect131r2(_) => EcCurve::Sect131r2,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
            Self::Sect163k1(_) => EcCurve::Sect163k1,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
            Self::Sect163r1(_) => EcCurve::Sect163r1,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
            Self::Sect163r2(_) => EcCurve::Sect163r2,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
            Self::Sect193r1(_) => EcCurve::Sect193r1,
            #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
            Self::Sect193r2(_) => EcCurve::Sect193r2,
            #[cfg(feature = "ec-f2m")]
            Self::Sect233k1(_) => EcCurve::Sect233k1,
            #[cfg(feature = "ec-f2m")]
            Self::Sect233r1(_) => EcCurve::Sect233r1,
            #[cfg(feature = "ec-f2m")]
            Self::Sect239k1(_) => EcCurve::Sect239k1,
            #[cfg(feature = "ec-f2m")]
            Self::Sect283k1(_) => EcCurve::Sect283k1,
            #[cfg(feature = "ec-f2m")]
            Self::Sect283r1(_) => EcCurve::Sect283r1,
            #[cfg(feature = "ec-f2m")]
            Self::Sect409k1(_) => EcCurve::Sect409k1,
            #[cfg(feature = "ec-f2m")]
            Self::Sect409r1(_) => EcCurve::Sect409r1,
            #[cfg(feature = "ec-f2m")]
            Self::Sect571k1(_) => EcCurve::Sect571k1,
            #[cfg(feature = "ec-f2m")]
            Self::Sect571r1(_) => EcCurve::Sect571r1,
        }
    }
}

// Shows the curve, which is public, and nothing of the key
impl fmt::Debug for AnyEcPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AnyEcPrivateKey")
            .field(&self.curve())
            .finish_non_exhaustive()
    }
}
