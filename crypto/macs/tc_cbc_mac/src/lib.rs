//! CBC block-cipher MAC with zero padding or caller-selected padding.

#![no_std]

mod engine;
mod error;

pub use engine::{CbcMac, CbcMacPadding, NoPadding, Params, WithPadding};
pub use error::{CreateError, Error, InitError};
