//! Output-feedback block cipher modes.
//!
//! [`FixedOfbBlockCipher`] keeps its state in const-sized arrays and requires
//! no allocation. The default `alloc` feature additionally provides the
//! runtime-sized `OfbBlockCipher`. [`GofbBlockCipher`] implements the
//! 64-bit GOST counter mode known as GCTR and also requires no allocation.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod fixed_ofb;
mod gofb;
#[cfg(feature = "alloc")]
mod ofb;

pub use fixed_ofb::FixedOfbBlockCipher;
pub use gofb::{BLOCK_BYTES as GCTR_BLOCK_BYTES, GofbBlockCipher};
#[cfg(feature = "alloc")]
pub use ofb::OfbBlockCipher;
