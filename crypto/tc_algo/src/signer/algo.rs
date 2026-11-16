#[cfg(any(feature = "dsa", feature = "ecdsa", feature = "ecnr"))]
mod digest_dsa;
#[cfg(feature = "dsa")]
mod dsa;
#[cfg(any(feature = "ecdsa", feature = "ecnr", feature = "ecgost3410"))]
mod ec;
#[cfg(any(feature = "ed25519", feature = "ed448"))]
mod eddsa;
#[cfg(feature = "gost3410")]
mod gost3410;
#[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
mod pqc;
#[cfg(any(
    feature = "rsa",
    feature = "dsa",
    feature = "ecdsa",
    feature = "ecnr",
    feature = "ecgost3410",
    feature = "gost3410",
    feature = "sm2",
    feature = "ed25519",
    feature = "ed448",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
mod row;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(feature = "sm2")]
mod sm2;

use super::SignerEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the signers whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "rsa")]
    rsa::rsa,
    #[cfg(feature = "dsa")]
    dsa::dsa,
    #[cfg(any(feature = "ecdsa", feature = "ecnr", feature = "ecgost3410"))]
    ec::ec,
    #[cfg(feature = "gost3410")]
    gost3410::gost3410,
    #[cfg(feature = "sm2")]
    sm2::sm2,
    #[cfg(any(feature = "ed25519", feature = "ed448"))]
    eddsa::eddsa,
    #[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
    pqc::pqc,
];
