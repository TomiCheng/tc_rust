//! DSTU message authentication codes.
//!
//! This crate currently provides [`Dstu7564Mac`], the keyed construction built
//! from the DSTU 7564 (Kupyna) digest.
//!
//! ```
//! use tc_dstu_macs::Dstu7564Mac;
//! use tc_macs::{Mac, MacInit};
//! use tc_params::KeyRef;
//!
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! let key = core::array::from_fn::<_, 32, _>(|index| (31 - index) as u8);
//! let params = KeyRef::new(&key);
//! let mut mac = Dstu7564Mac::new(256);
//!
//! mac.init(&params)?;
//! mac.update(b"authenticated message")?;
//!
//! let mut tag = [0_u8; 32];
//! assert_eq!(mac.do_final(&mut tag)?, tag.len());
//! # Ok(())
//! # }
//! ```

#![no_std]

extern crate alloc;

mod dstu7564;

pub use dstu7564::Dstu7564Mac;

/// Supported DSTU 7564 MAC lengths in bits.
pub const MAC_BITS: [usize; 3] = [256, 384, 512];
