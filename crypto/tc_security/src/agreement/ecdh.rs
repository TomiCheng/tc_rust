use tc_agreement::{Agreement, AgreementInit};
use tc_ecdh_v2::{EcdhBasicAgreement, EcdhError};

use super::AnyAgreement;
use crate::params::{AnyEcPrivateKey, AnyEcPublicKey, AnyParams, EcCurve, ec_domains};
use crate::{AnyError, SecurityError};

/// BC 的 `ECDHBasicAgreement`：init 時看私鑰在哪條曲線，建那條曲線的 agreement。
/// 公鑰要在同一條曲線上，不是的話回傳 `WrongParams`。
pub(super) struct EcdhAgreement(Option<AnyAgreement>);

impl EcdhAgreement {
    pub(super) fn new() -> Self {
        Self(None)
    }
}

impl AgreementInit<AnyParams> for EcdhAgreement {
    type Error = AnyError;

    fn init(&mut self, params: &AnyParams) -> Result<(), AnyError> {
        let AnyParams::EcPrivate { key } = params else {
            return Err(AnyError::new(SecurityError::WrongParams));
        };
        let mut agreement = on_curve(key.curve());
        agreement.init(params)?;
        self.0 = Some(agreement);
        Ok(())
    }
}

impl Agreement for EcdhAgreement {
    type PublicKey = AnyParams;
    type Error = AnyError;

    /// 曲線座標的 bytes 數；還沒 init 時不知道曲線，回傳 0。
    fn agreement_size(&self) -> usize {
        self.0.as_ref().map_or(0, AnyAgreement::agreement_size)
    }

    fn calculate_agreement(
        &self,
        public_key: &AnyParams,
        output: &mut [u8],
    ) -> Result<(), AnyError> {
        self.0
            .as_ref()
            .ok_or_else(|| AnyError::new(EcdhError::NotInitialized))?
            .calculate_agreement(public_key, output)
    }
}

// 每條曲線是不同的型別，所以一條曲線一個分支；金鑰從 AnyParams 取出那條曲線的型別
fn on_curve(curve: EcCurve) -> AnyAgreement {
    match curve {
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp112r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp112r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp112r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp112r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp112r2 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp112r2>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp112r2(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp112r2(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp128r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp128r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp128r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp128r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp128r2 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp128r2>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp128r2(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp128r2(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp160k1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp160k1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp160k1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp160k1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp160r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp160r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp160r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp160r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp160r2 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp160r2>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp160r2(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp160r2(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp192k1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp192k1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp192k1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp192k1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp192r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp192r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp192r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp192r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        EcCurve::Secp224k1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp224k1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp224k1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp224k1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        EcCurve::Secp224r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp224r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp224r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp224r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        EcCurve::Secp256k1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp256k1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp256k1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp256k1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        EcCurve::Secp256r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp256r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp256r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp256r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        EcCurve::Secp384r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp384r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp384r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp384r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        EcCurve::Secp521r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Secp521r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Secp521r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Secp521r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        EcCurve::Sm2p256v1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sm2p256v1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sm2p256v1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sm2p256v1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect113r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect113r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect113r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect113r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect113r2 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect113r2>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect113r2(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect113r2(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect131r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect131r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect131r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect131r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect131r2 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect131r2>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect131r2(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect131r2(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect163k1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect163k1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect163k1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect163k1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect163r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect163r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect163r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect163r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect163r2 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect163r2>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect163r2(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect163r2(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect193r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect193r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect193r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect193r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect193r2 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect193r2>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect193r2(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect193r2(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect233k1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect233k1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect233k1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect233k1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect233r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect233r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect233r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect233r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect239k1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect239k1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect239k1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect239k1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect283k1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect283k1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect283k1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect283k1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect283r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect283r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect283r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect283r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect409k1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect409k1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect409k1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect409k1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect409r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect409r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect409r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect409r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect571k1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect571k1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect571k1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect571k1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect571r1 => AnyAgreement::new(
            EcdhBasicAgreement::<ec_domains::Sect571r1>::new(),
            |params| match params {
                AnyParams::EcPrivate {
                    key: AnyEcPrivateKey::Sect571r1(key),
                } => Some(&**key),
                _ => None,
            },
            |params| match params {
                AnyParams::EcPublic {
                    key: AnyEcPublicKey::Sect571r1(key),
                } => Some(&**key),
                _ => None,
            },
        ),
    }
}
