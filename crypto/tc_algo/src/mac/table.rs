use std::sync::LazyLock;

use super::MacEntry;

// Built on first use, as the cipher table is: the HMAC rows come from the digest table
pub(super) static MACS: LazyLock<Vec<MacEntry>> = LazyLock::new(Vec::new);
