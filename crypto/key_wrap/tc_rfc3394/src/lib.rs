//! RFC 3394 key wrapping over a caller-selected 128-bit block cipher.
//!
//! The caller can provide its own parameter type. Returning `None` from
//! [`tc_params::OptionalIvParams::optional_iv`] selects RFC 3394's standard
//! IV; return an eight-byte value to use a protocol-defined custom IV.
//!
//! ```
//! use tc_aes::AesEngine;
//! use tc_cipher::{KeyWrap, KeyWrapInit, WrapDirection};
//! use tc_params::{KeyParams, OptionalIvParams};
//! use tc_rfc3394::Rfc3394WrapEngine;
//!
//! struct Params<'a> {
//!     key: &'a [u8],
//!     iv: Option<&'a [u8]>,
//! }
//!
//! impl KeyParams for Params<'_> {
//!     fn key(&self) -> &[u8] {
//!         self.key
//!     }
//! }
//!
//! impl OptionalIvParams for Params<'_> {
//!     fn optional_iv(&self) -> Option<&[u8]> {
//!         self.iv
//!     }
//! }
//!
//! let kek = [0x11; 16];
//! let key = [0x22; 16];
//! let params = Params {
//!     key: &kek,
//!     iv: None,
//! };
//! let mut wrapper = Rfc3394WrapEngine::new(AesEngine::new());
//!
//! wrapper.init(WrapDirection::Wrap, &params).unwrap();
//! let mut wrapped = [0u8; 24];
//! let wrapped_len = wrapper.wrap_into(&key, &mut wrapped).unwrap();
//!
//! wrapper.init(WrapDirection::Unwrap, &params).unwrap();
//! let mut recovered = [0u8; 16];
//! let recovered_len = wrapper
//!     .unwrap_into(&wrapped[..wrapped_len], &mut recovered)
//!     .unwrap();
//!
//! assert_eq!(&recovered[..recovered_len], key);
//! ```

#![no_std]

mod core;
mod engine;

#[doc(hidden)]
pub use core::{fixed_time_eq, unwrap_core_into, wrap_core_in_place};
pub use engine::Rfc3394WrapEngine;

/// RFC 3394 key-wrap operation error.
pub type Rfc3394Error<E> = tc_cipher::KeyWrapError<E>;
/// RFC 3394 key-wrapper initialization error.
pub type Rfc3394InitError<E> = tc_cipher::KeyWrapInitError<E>;
