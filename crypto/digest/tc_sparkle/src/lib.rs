//! SPARKLE ESCH-256 and ESCH-384 digest implementations.

#![no_std]

mod sparkle;

pub use sparkle::{SparkleDigest, SparkleParameters};
