//! CFB block-cipher MAC with configurable feedback and tag sizes.

#![no_std]

mod engine;
mod error;

pub use engine::{CfbMac, CfbMacPadding, NoPadding, Params, WithPadding};
pub use error::{CreateError, Error, InitError};
