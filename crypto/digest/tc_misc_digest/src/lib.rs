//! Less common message digests on the `tc_digest` traits, one feature each:
//! `haraka`, `photon-beetle`, `sparkle` (ESCH), `tiger`, `whirlpool` and
//! `xoodyak`. With `std`, Haraka selects AES-NI at runtime on x86.

#![no_std]

#[cfg(test)]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "haraka")]
pub mod haraka;
#[cfg(any(feature = "tiger", feature = "whirlpool"))]
mod md_buffer;
#[cfg(feature = "photon-beetle")]
pub mod photon_beetle;
#[cfg(feature = "sparkle")]
pub mod sparkle;
#[cfg(feature = "tiger")]
pub mod tiger;
#[cfg(feature = "whirlpool")]
pub mod whirlpool;
#[cfg(feature = "xoodyak")]
pub mod xoodyak;
