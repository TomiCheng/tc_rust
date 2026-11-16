#[cfg(any(feature = "ecdsa", feature = "ecnr"))]
mod ec;
#[cfg(any(feature = "rsa", feature = "ecdsa", feature = "ecnr", feature = "sm2"))]
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
    #[cfg(any(feature = "ecdsa", feature = "ecnr"))]
    ec::ec,
    #[cfg(feature = "sm2")]
    sm2::sm2,
];
