mod ed25519_ctx_signer;
mod ed25519_key;
mod ed25519_ph_signer;
mod ed25519_signer;
#[cfg(feature = "ed448")]
mod ed448_key;
#[cfg(feature = "ed448")]
mod ed448_ph_signer;
#[cfg(feature = "ed448")]
mod ed448_signer;

#[cfg(feature = "ed448")]
pub use ed448_ph_signer::Ed448PhSigner;
#[cfg(feature = "ed448")]
pub use ed448_signer::Ed448Signer;
pub use ed25519_ctx_signer::Ed25519CtxSigner;
pub use ed25519_ph_signer::Ed25519PhSigner;
pub use ed25519_signer::Ed25519Signer;
