//! MACs by name or OID, after Bouncy Castle's `MacUtilities`. A MAC is found by name, initialized
//! with an [`AnyMacParams`] that holds the key and, for the MACs that take one, an IV, then fed the
//! message for its tag.

mod any_mac;
mod any_mac_params;
mod dyn_mac;
mod entry;
mod functions;
mod helper;
mod table;

pub use any_mac::AnyMac;
pub use any_mac_params::AnyMacParams;
pub use entry::MacEntry;
pub use functions::{algorithms, get_by_name, get_by_oid};
pub use helper::calculate;
pub use tc_macs::{Mac, MacInit};
