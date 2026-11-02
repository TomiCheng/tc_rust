// One row per agreement; an agreement whose feature is off does not appear

#[cfg(feature = "dh")]
mod dh;
#[cfg(feature = "ecdh")]
mod ecdh;
#[cfg(feature = "x25519")]
mod x25519;

use super::AgreementEntry;

// In the order of Bouncy Castle's names
pub(super) const AGREEMENTS: &[AgreementEntry] = &[
    #[cfg(feature = "dh")]
    dh::DH,
    #[cfg(feature = "ecdh")]
    ecdh::ECDH,
    #[cfg(feature = "ecdh")]
    ecdh::ECDHC,
    #[cfg(feature = "x25519")]
    x25519::X25519,
];
