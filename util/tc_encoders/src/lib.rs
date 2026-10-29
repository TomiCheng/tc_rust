//! Hex、Base64 與 UrlBase64 編碼，移植自 Bouncy Castle 的 `Utilities.Encoders`。

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod errors;
pub mod hex;
mod traits;

pub use errors::EncoderError;
pub use traits::Encoder;
