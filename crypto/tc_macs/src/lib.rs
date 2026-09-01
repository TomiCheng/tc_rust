//! Shared message-authentication-code contracts.

#![no_std]

mod mac;

pub use mac::{Mac, MacInit};
