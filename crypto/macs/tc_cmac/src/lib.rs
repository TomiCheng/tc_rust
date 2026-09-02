//! Cipher-based message authentication code (CMAC).
//!
//! [`CMac`] accepts any 64- or 128-bit block cipher implementing the shared
//! `tc_cipher` contracts. It retains the final complete message block until
//! finalization, so callers may stream input in arbitrary chunk sizes without
//! allocating.
//!
//! ```
//! use tc_aes::AesEngine;
//! use tc_cmac::CMac;
//! use tc_macs::{Mac, MacInit};
//! use tc_params::KeyRef;
//!
//! // NIST SP 800-38B, AES-128 CMAC example 1 (empty message).
//! let key = [
//!     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//!     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
//! ];
//! let mut cmac = CMac::new(AesEngine::new()).unwrap();
//! cmac.init(&KeyRef::new(&key)).unwrap();
//! cmac.update(&[]).unwrap();
//!
//! let mut tag = [0_u8; 16];
//! cmac.do_final(&mut tag).unwrap();
//! assert_eq!(tag, [
//!     0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
//!     0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46,
//! ]);
//! ```

#![no_std]

mod engine;
mod error;

pub use engine::CMac;
pub use error::{CreateError, Error, InitError};
