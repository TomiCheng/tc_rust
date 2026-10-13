//! 依名稱或 OID 建立 key wrapper，對應 BC 的 `WrapperUtilities`。
//!
//! ```
//! # #[cfg(feature = "aes")] {
//! use tc_security::wrap;
//!
//! use tc_security::params::AnyParams;
//!
//! let entry = wrap::get_by_name("AESKW")?;
//! let params = AnyParams::new(vec![0x42; 16]);
//! let mut wrapper = entry.wrapper();
//!
//! let wrapped = wrap::wrap(&mut wrapper, &params, &[0x24; 16])?;
//! assert_eq!(wrapped.len(), 24);
//! assert_eq!(wrap::unwrap(&mut wrapper, &params, &wrapped)?, [0x24; 16]);
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod algorithms;
mod any_wrapper;
mod helpers;
mod table;
mod wrap_entry;

pub use algorithms::{algorithms, get_by_name, get_by_oid};
pub use any_wrapper::AnyWrapper;
pub use helpers::{unwrap, wrap};
pub use wrap_entry::WrapEntry;
