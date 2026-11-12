#[cfg(any(
    feature = "cmac",
    feature = "cbc-mac",
    feature = "cfb-mac",
    feature = "gmac"
))]
mod block;
#[cfg(feature = "hmac")]
mod hmac;
mod standalone;

use super::MacEntry;

// Built at run time, as the cipher table is: the HMAC rows come from the digest table
pub(super) fn build_table() -> Vec<MacEntry> {
    let mut rows = Vec::new();
    #[cfg(feature = "hmac")]
    rows.extend(hmac::rows());
    #[cfg(any(
        feature = "cmac",
        feature = "cbc-mac",
        feature = "cfb-mac",
        feature = "gmac"
    ))]
    rows.extend(block::rows());
    rows.extend(standalone::rows());
    rows
}

// The names of a row, of which the first is the canonical one
#[allow(dead_code, reason = "unused when every MAC feature is off")]
fn names(names: &[&str]) -> Vec<String> {
    names.iter().map(ToString::to_string).collect()
}
