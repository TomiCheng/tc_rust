use rand::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_ec_core::Curve;
use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator, EcPrivateKey, EcPublicKey};

use super::no_key;
use crate::generate::{GeneratorEntry, KeyGenParams};
use crate::params::{AnyEcPrivateKey, AnyEcPublicKey, AnyParams, EcCurve, ec_domains};
use crate::{AnyError, SecurityError};

// 曲線一定要明確指定：長度相同的曲線不只一條，從長度猜會默默選錯
fn check_params(params: &KeyGenParams) -> Result<(), SecurityError> {
    if matches!(params, KeyGenParams::Ec { .. }) {
        Ok(())
    } else {
        Err(SecurityError::InvalidKeyGenParams)
    }
}

fn key_pair<C>(
    g: C::Point,
    rng: &mut dyn CryptoRng,
    public: fn(Box<EcPublicKey<C>>) -> AnyEcPublicKey,
    private: fn(Box<EcPrivateKey<C>>) -> AnyEcPrivateKey,
) -> Result<(AnyEcPublicKey, AnyEcPrivateKey), AnyError>
where
    C: Curve<Scalar = PaddedBigUint>,
{
    let mut generator = EcKeyPairGenerator::<C>::new();
    generator
        .init(EcKeyGenerationParams::new(g, rng))
        .map_err(AnyError::new)?;
    let (public_key, private_key) = generator.generate_key_pair().map_err(AnyError::new)?;
    Ok((public(Box::new(public_key)), private(Box::new(private_key))))
}

// 每條曲線是不同的型別，所以一條曲線一個分支
fn generate_key_pair(
    params: &KeyGenParams,
    rng: &mut dyn CryptoRng,
) -> Result<(AnyParams, AnyParams), AnyError> {
    let KeyGenParams::Ec { curve } = *params else {
        return Err(AnyError::new(SecurityError::InvalidKeyGenParams));
    };
    let (public, private) = match curve {
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp112r1 => key_pair(
            ec_domains::secp112r1(),
            rng,
            AnyEcPublicKey::Secp112r1,
            AnyEcPrivateKey::Secp112r1,
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp112r2 => key_pair(
            ec_domains::secp112r2(),
            rng,
            AnyEcPublicKey::Secp112r2,
            AnyEcPrivateKey::Secp112r2,
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp128r1 => key_pair(
            ec_domains::secp128r1(),
            rng,
            AnyEcPublicKey::Secp128r1,
            AnyEcPrivateKey::Secp128r1,
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp128r2 => key_pair(
            ec_domains::secp128r2(),
            rng,
            AnyEcPublicKey::Secp128r2,
            AnyEcPrivateKey::Secp128r2,
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp160k1 => key_pair(
            ec_domains::secp160k1(),
            rng,
            AnyEcPublicKey::Secp160k1,
            AnyEcPrivateKey::Secp160k1,
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp160r1 => key_pair(
            ec_domains::secp160r1(),
            rng,
            AnyEcPublicKey::Secp160r1,
            AnyEcPrivateKey::Secp160r1,
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp160r2 => key_pair(
            ec_domains::secp160r2(),
            rng,
            AnyEcPublicKey::Secp160r2,
            AnyEcPrivateKey::Secp160r2,
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp192k1 => key_pair(
            ec_domains::secp192k1(),
            rng,
            AnyEcPublicKey::Secp192k1,
            AnyEcPrivateKey::Secp192k1,
        ),
        #[cfg(feature = "ec-small-curves")]
        EcCurve::Secp192r1 => key_pair(
            ec_domains::secp192r1(),
            rng,
            AnyEcPublicKey::Secp192r1,
            AnyEcPrivateKey::Secp192r1,
        ),
        EcCurve::Secp224k1 => key_pair(
            ec_domains::secp224k1(),
            rng,
            AnyEcPublicKey::Secp224k1,
            AnyEcPrivateKey::Secp224k1,
        ),
        EcCurve::Secp224r1 => key_pair(
            ec_domains::secp224r1(),
            rng,
            AnyEcPublicKey::Secp224r1,
            AnyEcPrivateKey::Secp224r1,
        ),
        EcCurve::Secp256k1 => key_pair(
            ec_domains::secp256k1(),
            rng,
            AnyEcPublicKey::Secp256k1,
            AnyEcPrivateKey::Secp256k1,
        ),
        EcCurve::Secp256r1 => key_pair(
            ec_domains::secp256r1(),
            rng,
            AnyEcPublicKey::Secp256r1,
            AnyEcPrivateKey::Secp256r1,
        ),
        EcCurve::Secp384r1 => key_pair(
            ec_domains::secp384r1(),
            rng,
            AnyEcPublicKey::Secp384r1,
            AnyEcPrivateKey::Secp384r1,
        ),
        EcCurve::Secp521r1 => key_pair(
            ec_domains::secp521r1(),
            rng,
            AnyEcPublicKey::Secp521r1,
            AnyEcPrivateKey::Secp521r1,
        ),
        EcCurve::Sm2p256v1 => key_pair(
            ec_domains::sm2p256v1(),
            rng,
            AnyEcPublicKey::Sm2p256v1,
            AnyEcPrivateKey::Sm2p256v1,
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect113r1 => key_pair(
            ec_domains::sect113r1(),
            rng,
            AnyEcPublicKey::Sect113r1,
            AnyEcPrivateKey::Sect113r1,
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect113r2 => key_pair(
            ec_domains::sect113r2(),
            rng,
            AnyEcPublicKey::Sect113r2,
            AnyEcPrivateKey::Sect113r2,
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect131r1 => key_pair(
            ec_domains::sect131r1(),
            rng,
            AnyEcPublicKey::Sect131r1,
            AnyEcPrivateKey::Sect131r1,
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect131r2 => key_pair(
            ec_domains::sect131r2(),
            rng,
            AnyEcPublicKey::Sect131r2,
            AnyEcPrivateKey::Sect131r2,
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect163k1 => key_pair(
            ec_domains::sect163k1(),
            rng,
            AnyEcPublicKey::Sect163k1,
            AnyEcPrivateKey::Sect163k1,
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect163r1 => key_pair(
            ec_domains::sect163r1(),
            rng,
            AnyEcPublicKey::Sect163r1,
            AnyEcPrivateKey::Sect163r1,
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect163r2 => key_pair(
            ec_domains::sect163r2(),
            rng,
            AnyEcPublicKey::Sect163r2,
            AnyEcPrivateKey::Sect163r2,
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect193r1 => key_pair(
            ec_domains::sect193r1(),
            rng,
            AnyEcPublicKey::Sect193r1,
            AnyEcPrivateKey::Sect193r1,
        ),
        #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
        EcCurve::Sect193r2 => key_pair(
            ec_domains::sect193r2(),
            rng,
            AnyEcPublicKey::Sect193r2,
            AnyEcPrivateKey::Sect193r2,
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect233k1 => key_pair(
            ec_domains::sect233k1(),
            rng,
            AnyEcPublicKey::Sect233k1,
            AnyEcPrivateKey::Sect233k1,
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect233r1 => key_pair(
            ec_domains::sect233r1(),
            rng,
            AnyEcPublicKey::Sect233r1,
            AnyEcPrivateKey::Sect233r1,
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect239k1 => key_pair(
            ec_domains::sect239k1(),
            rng,
            AnyEcPublicKey::Sect239k1,
            AnyEcPrivateKey::Sect239k1,
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect283k1 => key_pair(
            ec_domains::sect283k1(),
            rng,
            AnyEcPublicKey::Sect283k1,
            AnyEcPrivateKey::Sect283k1,
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect283r1 => key_pair(
            ec_domains::sect283r1(),
            rng,
            AnyEcPublicKey::Sect283r1,
            AnyEcPrivateKey::Sect283r1,
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect409k1 => key_pair(
            ec_domains::sect409k1(),
            rng,
            AnyEcPublicKey::Sect409k1,
            AnyEcPrivateKey::Sect409k1,
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect409r1 => key_pair(
            ec_domains::sect409r1(),
            rng,
            AnyEcPublicKey::Sect409r1,
            AnyEcPrivateKey::Sect409r1,
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect571k1 => key_pair(
            ec_domains::sect571k1(),
            rng,
            AnyEcPublicKey::Sect571k1,
            AnyEcPrivateKey::Sect571k1,
        ),
        #[cfg(feature = "ec-f2m")]
        EcCurve::Sect571r1 => key_pair(
            ec_domains::sect571r1(),
            rng,
            AnyEcPublicKey::Sect571r1,
            AnyEcPrivateKey::Sect571r1,
        ),
    }?;
    Ok((
        AnyParams::EcPublic { key: public },
        AnyParams::EcPrivate { key: private },
    ))
}

/// 沒有預設曲線，一定要先用 `KeyGenParams::Ec` 呼叫 `init`；BC 的 ECDH、ECIES、ECDSA 都對到這一列。
pub(super) const EC: GeneratorEntry = GeneratorEntry::without_default(
    &["EC", "ECDH", "ECIES", "ECDSA"],
    &[],
    check_params,
    no_key,
    generate_key_pair,
);
