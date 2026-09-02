//! Shared message-authentication-code contracts.

#![no_std]

mod mac;
mod mac_error;

pub use mac::{Mac, MacInit};
pub use mac_error::{MacError, MacInitError};
