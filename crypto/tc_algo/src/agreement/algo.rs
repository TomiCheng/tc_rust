#[cfg(any(feature = "x25519", feature = "x448"))]
mod cfrg;
#[cfg(feature = "dh")]
mod dh;
#[cfg(any(feature = "ecdh", feature = "ecdhc", feature = "ecmqv"))]
mod ec;
#[cfg(any(
    feature = "ecdh",
    feature = "ecdhc",
    feature = "ecmqv",
    feature = "ecgost3410",
    feature = "x25519",
    feature = "x448"
))]
mod typed;
#[cfg(feature = "ecgost3410")]
mod vko;

use super::AgreementEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn AgreementEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the agreements whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "dh")]
    dh::dh,
    #[cfg(any(feature = "ecdh", feature = "ecdhc", feature = "ecmqv"))]
    ec::ec,
    #[cfg(feature = "ecgost3410")]
    vko::vko,
    #[cfg(any(feature = "x25519", feature = "x448"))]
    cfrg::cfrg,
];
