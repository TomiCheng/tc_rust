mod ed25519_key_pair_generator;
#[cfg(feature = "ed448")]
mod ed448_key_pair_generator;
mod x25519_key_pair_generator;
#[cfg(feature = "x448")]
mod x448_key_pair_generator;

#[cfg(feature = "ed448")]
pub use ed448_key_pair_generator::Ed448KeyPairGenerator;
pub use ed25519_key_pair_generator::Ed25519KeyPairGenerator;
#[cfg(feature = "x448")]
pub use x448_key_pair_generator::X448KeyPairGenerator;
pub use x25519_key_pair_generator::X25519KeyPairGenerator;
