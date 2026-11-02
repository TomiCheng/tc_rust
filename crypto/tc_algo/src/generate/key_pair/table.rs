// One row per generator; an algorithm whose feature is off does not appear

#[cfg(feature = "dh")]
mod dh;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(feature = "x25519")]
mod x25519;

use super::KeyPairGeneratorEntry;

pub(super) const KEY_PAIR_GENERATORS: &[KeyPairGeneratorEntry] = &[
    #[cfg(feature = "dh")]
    dh::DH,
    #[cfg(feature = "rsa")]
    rsa::RSA,
    #[cfg(feature = "x25519")]
    x25519::X25519,
];
