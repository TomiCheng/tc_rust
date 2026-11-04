#[cfg(feature = "hmac")]
mod hmac;

use std::sync::LazyLock;

use super::MacEntry;

// Built on first use, as the cipher table is: the HMAC rows come from the digest table
pub(super) static MACS: LazyLock<Vec<MacEntry>> = LazyLock::new(|| {
    #[allow(unused_mut, reason = "nothing is added when every MAC feature is off")]
    let mut rows = Vec::new();
    #[cfg(feature = "hmac")]
    rows.extend(hmac::rows());
    rows
});
