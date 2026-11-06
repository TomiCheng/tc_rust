#[cfg(feature = "ies")]
mod ies_dh_params;
mod key_length;

#[cfg(any(
    feature = "aes",
    feature = "chacha",
    feature = "hmac-sha256",
    feature = "rsa",
    feature = "dh",
    feature = "hkdf",
    feature = "ml-kem"
))]
use core::any::Any;

#[cfg(feature = "ies")]
pub use ies_dh_params::IesDhParams;
pub use key_length::KeyLength;
#[cfg(feature = "aes")]
pub use tc_aead_cipher::AeadParamsOwned;
#[cfg(any(feature = "aes", feature = "chacha", feature = "hmac-sha256"))]
pub use tc_block_cipher::{KeyOwned, KeyParams};
#[cfg(any(feature = "aes", feature = "chacha"))]
pub use tc_block_modes::{IvParams, KeyWithIvOwned};
#[cfg(feature = "dh")]
pub use tc_dh_key::standard_groups as dh_groups;
#[cfg(feature = "dh")]
pub use tc_dh_key::{DhParameters, DhPrivateKey, DhPublicKey};
#[cfg(feature = "hkdf")]
pub use tc_kdf::hkdf::HkdfParamsOwned;
#[cfg(feature = "ml-kem")]
pub use tc_ml_kem::{MlKemParameters, MlKemPrivateKey, MlKemPublicKey};
#[cfg(feature = "rsa")]
pub use tc_rsa::{RsaKey, RsaKeyGenerationParamsOwned, RsaKeyParams};

#[cfg(any(
    feature = "aes",
    feature = "chacha",
    feature = "hmac-sha256",
    feature = "rsa",
    feature = "dh",
    feature = "hkdf",
    feature = "ml-kem"
))]
use crate::Params;

#[cfg(any(feature = "aes", feature = "chacha", feature = "hmac-sha256"))]
impl Params for KeyOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(any(feature = "aes", feature = "chacha"))]
impl Params for KeyWithIvOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "aes")]
impl Params for AeadParamsOwned {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "hkdf")]
impl Params for HkdfParamsOwned {
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
impl Params for RsaKeyGenerationParamsOwned {
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
