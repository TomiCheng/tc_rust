//! DSTU message authentication codes.
//!
//! This crate provides [`Dstu7564Mac`], the keyed construction built from the
//! DSTU 7564 (Kupyna) digest, and [`Dstu7624Mac`], built from the DSTU 7624
//! (Kalyna) block cipher.
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
mod dstu7624;

pub use dstu7564::Dstu7564Mac;
pub use dstu7624::{
    Dstu7624Mac, Dstu7624Mac128, Dstu7624Mac256, Dstu7624Mac512, Dstu7624MacCreateError,
};

/// Supported DSTU 7564 MAC lengths in bits.
pub const MAC_BITS: [usize; 3] = [256, 384, 512];
