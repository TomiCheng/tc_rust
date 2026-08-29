//! Block cipher modes of operation, ported from Bouncy Castle's `Modes` package.
//!
//! A mode wraps a block cipher and adds the state that turns a single-block
//! permutation into a way of processing a longer message, so each mode both
//! implements and builds on the [`BlockCipher`](tc_cipher_core::BlockCipher) and
//! [`BlockCipherInit`](tc_cipher_core::BlockCipherInit) traits from
//! `tc_cipher_core`.
//!
//! Modes are generic over the underlying cipher, so this crate depends only on
//! the trait crate; concrete engines are needed by its tests alone.
//!
//! A mode reports a composed algorithm name (`"AES/ECB"`), which is built at
//! runtime, so the crate is `no_std` with an `alloc` requirement.

#![no_std]

extern crate alloc;

pub mod cbc;
pub mod ecb;

pub use cbc::{CbcBlockCipher, CbcError, CbcParams};
pub use ecb::EcbBlockCipher;
