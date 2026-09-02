//! Counter block cipher modes.
//!
//! CTR is also known as SIC. KCTR is the little-endian counter construction
//! used with DSTU 7624. Both modes expose block and stream interfaces. Their
//! fixed-size forms require no allocation; the default `alloc` feature also
//! provides runtime-sized forms.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod fixed_kctr;
mod fixed_sic;
#[cfg(feature = "alloc")]
mod kctr;
#[cfg(feature = "alloc")]
mod sic;

pub use fixed_kctr::FixedKctrBlockCipher;
pub use fixed_sic::FixedSicBlockCipher;
/// Allocation-free CTR mode with an `N`-byte block.
pub type FixedCtrBlockCipher<C, const N: usize> = FixedSicBlockCipher<C, N>;

#[cfg(feature = "alloc")]
pub use kctr::KctrBlockCipher;
#[cfg(feature = "alloc")]
pub use sic::SicBlockCipher;
/// Runtime-sized CTR mode.
#[cfg(feature = "alloc")]
pub type CtrBlockCipher<C> = SicBlockCipher<C>;
