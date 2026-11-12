// One row per agreement; an agreement whose feature is off does not appear

#[cfg(feature = "dh")]
mod dh;
#[cfg(feature = "ecdh")]
mod ecdh;
#[cfg(feature = "ecmqv")]
mod ecmqv;
#[cfg(feature = "ecvko")]
mod ecvko;
#[cfg(feature = "x25519")]
mod x25519;
#[cfg(feature = "x448")]
mod x448;

use super::AgreementEntry;

// In the order of Bouncy Castle's names
pub(super) const AGREEMENTS: &[AgreementEntry] = &[
    #[cfg(feature = "dh")]
    dh::DH,
    #[cfg(feature = "ecdh")]
    ecdh::ECDH,
    #[cfg(feature = "ecdh")]
    ecdh::ECDHC,
    #[cfg(feature = "ecmqv")]
    ecmqv::ECMQV,
    #[cfg(feature = "x25519")]
    x25519::X25519,
    #[cfg(feature = "x448")]
    x448::X448,
    #[cfg(all(feature = "ecvko", feature = "gost3411"))]
    ecvko::ECGOST3410,
    #[cfg(feature = "ecvko")]
    ecvko::ECGOST3410_2012_256,
    #[cfg(feature = "ecvko")]
    ecvko::ECGOST3410_2012_512,
];
