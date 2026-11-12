// One row per generator; an algorithm whose feature is off does not appear

#[cfg(feature = "aes")]
mod aes;

#[allow(
    unused_imports,
    reason = "unused when every symmetric key feature is off"
)]
use rand_core::{CryptoRng, Rng};

use super::KeyGeneratorEntry;
#[allow(
    unused_imports,
    reason = "unused when every symmetric key feature is off"
)]
use crate::params::SecretKey;

pub(super) const KEY_GENERATORS: &[KeyGeneratorEntry] = &[
    #[cfg(feature = "aes")]
    aes::AES,
    #[cfg(feature = "aes")]
    aes::AES128,
    #[cfg(feature = "aes")]
    aes::AES192,
    #[cfg(feature = "aes")]
    aes::AES256,
];

// A key of uniformly random bytes, as Bouncy Castle's CipherKeyGenerator makes for most ciphers
#[allow(dead_code, reason = "unused when every symmetric key feature is off")]
fn random_key(bits: usize, rng: &mut dyn CryptoRng) -> SecretKey {
    let mut key = vec![0; bits.div_ceil(8)];
    rng.fill_bytes(&mut key);
    SecretKey::new(key)
}
