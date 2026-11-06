mod key_length;

#[cfg(any(
    feature = "aes",
    feature = "chacha",
    feature = "hmac-sha256",
    feature = "rsa"
))]
use core::any::Any;

pub use key_length::KeyLength;
#[cfg(feature = "aes")]
pub use tc_aead_cipher::AeadParamsOwned;
#[cfg(any(feature = "aes", feature = "chacha", feature = "hmac-sha256"))]
pub use tc_block_cipher::{KeyOwned, KeyParams};
#[cfg(any(feature = "aes", feature = "chacha"))]
pub use tc_block_modes::{IvParams, KeyWithIvOwned};
#[cfg(feature = "rsa")]
pub use tc_rsa::{RsaKey, RsaKeyGenerationParamsOwned, RsaKeyParams};

#[cfg(any(
    feature = "aes",
    feature = "chacha",
    feature = "hmac-sha256",
    feature = "rsa"
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
