//! Block cipher modes of operation on top of `tc_block_cipher`: ECB, CBC, CFB,
//! OFB and CTR.

#![no_std]
#[cfg(feature = "alloc")]
extern crate alloc;

mod cbc;
mod cfb;
mod ctr;
mod ecb;
mod error;
mod ofb;
mod params;
mod traits;

#[cfg(feature = "alloc")]
pub use cbc::CbcBlockCipher;
pub use cbc::FixedCbcBlockCipher;
#[cfg(feature = "alloc")]
pub use cfb::CfbBlockCipher;
pub use cfb::FixedCfbBlockCipher;
#[cfg(feature = "alloc")]
pub use ctr::{CtrBlockCipher, SicBlockCipher};
pub use ctr::{FixedCtrBlockCipher, FixedSicBlockCipher};
pub use ecb::EcbBlockCipher;
pub use error::BlockModeError;
pub use error::BlockModeInitError;
#[cfg(feature = "alloc")]
pub use ofb::OfbBlockCipher;
pub use ofb::FixedOfbBlockCipher;
#[cfg(feature = "alloc")]
pub use params::KeyWithIvOwned;
pub use params::{KeyWithIvFixed, KeyWithIvRef};
pub use traits::BlockCipherMode;
pub use traits::IvOptParams;
pub use traits::IvParams;
