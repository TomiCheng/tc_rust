#[cfg(feature = "alloc")]
mod key;
#[cfg(feature = "alloc")]
mod key_generation_params_owned;
#[cfg(feature = "alloc")]
mod key_generation_params_ref;
mod key_owned;
mod key_ref;
#[cfg(feature = "rustcrypto")]
mod key_rustcrypto;
mod private_crt_key_owned;
mod private_crt_key_ref;
#[cfg(feature = "rustcrypto")]
mod private_crt_key_rustcrypto;

#[cfg(feature = "alloc")]
pub use key::RsaKey;
#[cfg(feature = "alloc")]
pub use key_generation_params_owned::RsaKeyGenerationParamsOwned;
#[cfg(feature = "alloc")]
pub use key_generation_params_ref::RsaKeyGenerationParamsRef;
pub use key_owned::RsaKeyOwned;
pub use key_ref::RsaKeyRef;
#[cfg(feature = "rustcrypto")]
pub use key_rustcrypto::RsaKeyRustCrypto;
pub use private_crt_key_owned::RsaPrivateCrtKeyOwned;
pub use private_crt_key_ref::RsaPrivateCrtKeyRef;
#[cfg(feature = "rustcrypto")]
pub use private_crt_key_rustcrypto::RsaPrivateCrtKeyRustCrypto;
