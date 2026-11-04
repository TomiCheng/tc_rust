//! Skein-MAC，對應 Bouncy Castle 的 `SkeinMac`。常數時間；長度視為公開值。

#![no_std]
#![forbid(unsafe_code)]

mod skein_mac;

pub use skein_mac::SkeinMac;
pub use tc_skein::{SkeinParams, SkeinParamsRef};
