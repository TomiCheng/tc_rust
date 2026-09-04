//! Fixed-precision big integer primitives for cryptographic use.
//!
//! Multi-limb integers use little-endian limb order: limb zero is the least
//! significant limb. Byte encoders and decoders may expose either byte order.

#![no_std]

extern crate alloc;

mod big_int;
mod big_uint;
mod fixed_big_int;
mod fixed_big_uint;
mod limb;
mod types;
mod word;

pub use big_int::BigInt;
pub use big_uint::BigUint;
pub use fixed_big_int::FixedBigInt;
pub use fixed_big_uint::FixedBigUint;
pub use limb::Limb;
pub use types::{I64, I128, I1024, U64, U128, U1024};
pub use word::{WideWord, Word};
