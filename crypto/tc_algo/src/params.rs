#[cfg(any(
    feature = "fp-custom",
    feature = "fp-curve",
    feature = "f2m-custom",
    feature = "f2m-curve"
))]
pub(crate) mod ec_curves;

use core::any::Any;

#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "cast",
    feature = "misc-block-cipher",
    feature = "rc-cipher",
    feature = "gost28147",
    feature = "threefish",
    feature = "chacha-aead",
    feature = "ascon-aead",
    feature = "grain128-aead",
    feature = "sparkle-aead"
))]
use tc_aead_cipher::AeadParamsOwned;
#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
use tc_aead_cipher::ParamsWithAeadOwned;
use tc_block_cipher::KeyOwned;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "cast",
    feature = "misc-block-cipher",
    feature = "rc-cipher",
    feature = "gost28147",
    feature = "threefish",
    feature = "chacha",
    feature = "rc4-family",
    feature = "salsa20",
    feature = "hc",
    feature = "chacha-aead",
    feature = "ascon-aead",
    feature = "grain128-aead",
    feature = "sparkle-aead",
    feature = "macs",
    feature = "pbe"
))]
use tc_block_modes::KeyWithIvOwned;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "cast",
    feature = "misc-block-cipher",
    feature = "rc-cipher",
    feature = "gost28147",
    feature = "threefish",
    feature = "chacha",
    feature = "rc4-family",
    feature = "salsa20",
    feature = "hc",
    feature = "chacha-aead",
    feature = "ascon-aead",
    feature = "grain128-aead",
    feature = "sparkle-aead",
    feature = "macs",
    feature = "pbe"
))]
use tc_block_modes::ParamsWithIvOwned;
#[cfg(feature = "cfrg-curves")]
use tc_cfrg_curves::{Ed448PrivateKey, Ed448PublicKey};
#[cfg(feature = "cfrg-curves")]
use tc_cfrg_curves::{Ed25519PrivateKey, Ed25519PublicKey};
#[cfg(feature = "cfrg-curves")]
use tc_cfrg_curves::{X448PrivateKey, X448PublicKey};
#[cfg(feature = "cfrg-curves")]
use tc_cfrg_curves::{X25519PrivateKey, X25519PublicKey};
#[cfg(feature = "dh")]
use tc_dh_key::DhParameters;
#[cfg(feature = "dh")]
use tc_dh_key::{DhPrivateKey, DhPublicKey};
#[cfg(feature = "dsa")]
use tc_dsa_signer::{DsaParameters, DsaPrivateKey, DsaPublicKey};
#[cfg(all(
    feature = "ec-agreement",
    feature = "gost3411",
    any(
        feature = "fp-custom",
        feature = "fp-curve",
        feature = "f2m-custom",
        feature = "f2m-curve"
    )
))]
use tc_ec_agreement::EcVkoParams;
#[cfg(all(
    feature = "ec-agreement",
    any(
        feature = "fp-custom",
        feature = "fp-curve",
        feature = "f2m-custom",
        feature = "f2m-curve"
    )
))]
use tc_ec_agreement::{MqvPrivateParams, MqvPublicParams};
#[cfg(all(
    feature = "ec-agreement",
    any(
        feature = "fp-custom",
        feature = "fp-curve",
        feature = "f2m-custom",
        feature = "f2m-curve"
    )
))]
use tc_ecdh_kek::UkmParams;
#[cfg(feature = "gost3410")]
use tc_gost3410::{Gost3410Parameters, Gost3410PrivateKey, Gost3410PublicKey};
#[cfg(feature = "gost28147")]
use tc_gost28147::Gost28147ParamsOwned;
#[cfg(feature = "kdf")]
use tc_kdf::hkdf::HkdfParamsOwned;
#[cfg(feature = "kdf")]
use tc_kdf::kdf::KdfParamsOwned;
#[cfg(feature = "kdf")]
use tc_kdf::sp800_108::{
    KdfCounterParamsOwned, KdfDoublePipelineParamsOwned, KdfFeedbackParamsOwned,
};
#[cfg(feature = "ml-dsa")]
use tc_ml_dsa::{MlDsaParameters, MlDsaPrivateKey, MlDsaPublicKey};
#[cfg(feature = "ml-kem")]
use tc_ml_kem::{MlKemParameters, MlKemPrivateKey, MlKemPublicKey};
#[cfg(feature = "pbe")]
use tc_pbe::PbeParamsOwned;
#[cfg(feature = "rc-cipher")]
use tc_rc_cipher::Rc2ParamsOwned;
#[cfg(feature = "rc-cipher")]
use tc_rc_cipher::Rc5ParamsOwned;
#[cfg(feature = "rsa")]
use tc_rsa::RsaKey;
#[cfg(feature = "slh-dsa")]
use tc_slh_dsa::{SlhDsaParameters, SlhDsaPrivateKey, SlhDsaPublicKey};
#[cfg(feature = "threefish")]
use tc_threefish::ThreefishParamsOwned;

use crate::Params;

impl Params for KeyOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "cast",
    feature = "misc-block-cipher",
    feature = "rc-cipher",
    feature = "gost28147",
    feature = "threefish",
    feature = "chacha",
    feature = "rc4-family",
    feature = "salsa20",
    feature = "hc",
    feature = "chacha-aead",
    feature = "ascon-aead",
    feature = "grain128-aead",
    feature = "sparkle-aead",
    feature = "macs",
    feature = "pbe"
))]
impl Params for KeyWithIvOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// An engine's own params with an IV, as Bouncy Castle's ParametersWithIV. Each TParams is a type
// of its own, which a row downcasts to
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "cast",
    feature = "misc-block-cipher",
    feature = "rc-cipher",
    feature = "gost28147",
    feature = "threefish",
    feature = "chacha",
    feature = "rc4-family",
    feature = "salsa20",
    feature = "hc",
    feature = "chacha-aead",
    feature = "ascon-aead",
    feature = "grain128-aead",
    feature = "sparkle-aead",
    feature = "macs",
    feature = "pbe"
))]
impl<TParams: Send + Sync + 'static> Params for ParamsWithIvOwned<TParams> {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// An engine's own params with the nonce, tag size and initial AAD of an AEAD mode, which gives the
// engine the own params alone
#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
impl<TParams: Send + Sync + 'static> Params for ParamsWithAeadOwned<TParams> {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "rc-cipher")]
impl Params for Rc2ParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "rc-cipher")]
impl Params for Rc5ParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "gost28147")]
impl Params for Gost28147ParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "threefish")]
impl Params for ThreefishParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "cast",
    feature = "misc-block-cipher",
    feature = "rc-cipher",
    feature = "gost28147",
    feature = "threefish",
    feature = "chacha-aead",
    feature = "ascon-aead",
    feature = "grain128-aead",
    feature = "sparkle-aead"
))]
impl Params for AeadParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "kdf")]
impl Params for HkdfParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "pbe")]
impl Params for PbeParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "kdf")]
impl Params for KdfParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "kdf")]
impl Params for KdfCounterParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "kdf")]
impl Params for KdfFeedbackParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "kdf")]
impl Params for KdfDoublePipelineParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "ml-kem")]
impl Params for MlKemParameters {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "ml-kem")]
impl Params for MlKemPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "ml-kem")]
impl Params for MlKemPrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "rsa")]
impl Params for RsaKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// The keys and the group of ElGamal encryption, from tc_elgamal
#[cfg(feature = "elgamal")]
impl Params for tc_elgamal::ElGamalPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "elgamal")]
impl Params for tc_elgamal::ElGamalPrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "elgamal")]
impl Params for tc_elgamal::ElGamalParameters {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// The keys of Naccache-Stern and the params of its key pair generator, which tc_naccache_stern has
#[cfg(feature = "naccache-stern")]
impl Params for tc_naccache_stern::NaccacheSternPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "naccache-stern")]
impl Params for tc_naccache_stern::NaccacheSternPrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "naccache-stern")]
impl Params for tc_naccache_stern::NaccacheSternKeyGenerationParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// The EC keys of tc_ec_key on a 'static curve, as the EC and SM2 key pair generators give them
#[cfg(any(
    feature = "sm2",
    feature = "fp-custom",
    feature = "fp-curve",
    feature = "f2m-custom",
    feature = "f2m-curve"
))]
impl<C> Params for tc_ec_key::EcPublicKey<C>
where
    C: tc_ec_core::Curve + 'static,
    tc_ec_key::EcPublicKey<C>: Send + Sync,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(any(
    feature = "sm2",
    feature = "fp-custom",
    feature = "fp-curve",
    feature = "f2m-custom",
    feature = "f2m-curve"
))]
impl<C> Params for tc_ec_key::EcPrivateKey<C>
where
    C: tc_ec_core::Curve<Scalar = tc_bigint::PaddedBigUint> + 'static,
    tc_ec_key::EcPrivateKey<C>: Send + Sync,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(any(feature = "dh", feature = "elgamal"))]
impl Params for tc_dh_key::DhGroupGenerationParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "dh")]
impl Params for DhParameters {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "dh")]
impl Params for DhPrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "dh")]
impl Params for DhPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "dsa")]
impl Params for DsaParameters {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "dsa")]
impl Params for DsaPrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "dsa")]
impl Params for DsaPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "gost3410")]
impl Params for Gost3410Parameters {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "gost3410")]
impl Params for Gost3410PrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "gost3410")]
impl Params for Gost3410PublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "cfrg-curves")]
impl Params for Ed25519PrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "cfrg-curves")]
impl Params for Ed25519PublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "cfrg-curves")]
impl Params for Ed448PrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "cfrg-curves")]
impl Params for Ed448PublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "cfrg-curves")]
impl Params for X25519PrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "cfrg-curves")]
impl Params for X25519PublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "cfrg-curves")]
impl Params for X448PrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "cfrg-curves")]
impl Params for X448PublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// A private key of an agreement with a KDF, with the UKM the KDF takes, as Bouncy Castle's
// ParametersWithUkm wraps it
#[cfg(all(
    feature = "ec-agreement",
    any(
        feature = "fp-custom",
        feature = "fp-curve",
        feature = "f2m-custom",
        feature = "f2m-curve"
    )
))]
impl<P: Send + Sync + 'static> Params for UkmParams<P> {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(all(
    feature = "ec-agreement",
    any(
        feature = "fp-custom",
        feature = "fp-curve",
        feature = "f2m-custom",
        feature = "f2m-curve"
    )
))]
impl<C> Params for MqvPrivateParams<C>
where
    C: tc_ec_core::Curve<Scalar = tc_bigint::PaddedBigUint> + 'static,
    MqvPrivateParams<C>: Send + Sync,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(all(
    feature = "ec-agreement",
    any(
        feature = "fp-custom",
        feature = "fp-curve",
        feature = "f2m-custom",
        feature = "f2m-curve"
    )
))]
impl<C> Params for MqvPublicParams<C>
where
    C: tc_ec_core::Curve + 'static,
    MqvPublicParams<C>: Send + Sync,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(all(
    feature = "ec-agreement",
    feature = "gost3411",
    any(
        feature = "fp-custom",
        feature = "fp-curve",
        feature = "f2m-custom",
        feature = "f2m-curve"
    )
))]
impl<C> Params for EcVkoParams<C>
where
    C: tc_ec_core::Curve<Scalar = tc_bigint::PaddedBigUint> + 'static,
    EcVkoParams<C>: Send + Sync,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "ml-dsa")]
impl Params for MlDsaParameters {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "ml-dsa")]
impl Params for MlDsaPrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "ml-dsa")]
impl Params for MlDsaPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "slh-dsa")]
impl Params for SlhDsaParameters {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "slh-dsa")]
impl Params for SlhDsaPrivateKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "slh-dsa")]
impl Params for SlhDsaPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub mod agreement;
pub mod cipher;
pub mod drbg;
pub mod generate;
pub mod kdf;
pub mod kem;
pub mod key;
pub mod mac;
pub mod pbe;
pub mod signer;
pub mod wrap;
pub mod xof;
