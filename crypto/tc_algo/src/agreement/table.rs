// One row per agreement; an agreement whose feature is off does not appear

#[cfg(feature = "dh")]
mod dh;

use super::AgreementEntry;

// In the order of Bouncy Castle's names
pub(super) const AGREEMENTS: &[AgreementEntry] = &[
    #[cfg(feature = "dh")]
    dh::DH,
];
