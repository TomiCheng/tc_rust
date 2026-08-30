//! Block cipher modes of operation, ported from Bouncy Castle's `Modes` package.
//!
//! A mode wraps a block cipher and adds the state that turns a single-block
//! permutation into a way of processing a longer message, so each mode both
//! implements and builds on the [`BlockCipher`](tc_cipher_core::BlockCipher) and
//! [`BlockCipherInit`](tc_cipher_core::BlockCipherInit) traits from
//! `tc_cipher_core`. All modes report failures through the shared
//! [`BlockCipherModeError`] type.
//!
//! Modes are generic over the underlying cipher, so this crate depends only on
//! the trait crate; concrete engines are needed by its tests alone.
//!
//! A mode reports a composed algorithm name (`"AES/CBC"`), which is built at
//! runtime, so the crate is `no_std` with an `alloc` requirement.

#![no_std]

extern crate alloc;

pub mod cbc;
pub mod cfb;
pub mod ecb;
mod error;
pub mod gofb;
pub mod kctr;
pub mod ofb;
pub mod openpgp_cfb;
pub mod sic;

pub use cbc::{CbcBlockCipher, CbcParams};
pub use cfb::{CfbBlockCipher, CfbParams};
pub use ecb::EcbBlockCipher;
pub use error::BlockCipherModeError;
pub use gofb::{GofbBlockCipher, GofbParams};
pub use kctr::{KCtrBlockCipher, KCtrParams};
pub use ofb::{OfbBlockCipher, OfbParams};
pub use openpgp_cfb::{OpenPgpCfbBlockCipher, OpenPgpCfbParams};
pub use sic::{CtrBlockCipher, CtrParams, SicBlockCipher, SicParams};
