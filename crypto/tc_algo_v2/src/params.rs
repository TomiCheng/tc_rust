#[cfg(feature = "ascon-cxof128")]
mod ascon_cxof_params;
#[cfg(feature = "blake2xs")]
mod blake2xs_params;
#[cfg(feature = "blake3")]
mod blake3_params;
#[cfg(any(feature = "cshake128", feature = "cshake256"))]
mod cshake_params;
#[cfg(feature = "drbg-hmac-sha256")]
mod drbg_params;
#[cfg(feature = "ies")]
mod ies_dh_params;
mod key_length;
#[cfg(feature = "rsa")]
mod rsa_key_gen_params;
#[cfg(any(feature = "tuplehash128", feature = "tuplehash256"))]
mod tuple_hash_params;

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

#[cfg(feature = "ascon-cxof128")]
pub use ascon_cxof_params::AsconCXofParams;
#[cfg(feature = "blake2xs")]
pub use blake2xs_params::Blake2xsParams;
#[cfg(feature = "blake3")]
pub use blake3_params::Blake3Params;
#[cfg(any(feature = "cshake128", feature = "cshake256"))]
pub use cshake_params::CShakeParams;
#[cfg(feature = "drbg-hmac-sha256")]
pub use drbg_params::DrbgParams;
#[cfg(feature = "ies")]
pub use ies_dh_params::IesDhParams;
pub use key_length::KeyLength;
#[cfg(feature = "rsa")]
pub use rsa_key_gen_params::RsaKeyGenParams;
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
pub use tc_rsa::{RsaKey, RsaKeyParams};
#[cfg(any(feature = "tuplehash128", feature = "tuplehash256"))]
pub use tuple_hash_params::TupleHashParams;

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
