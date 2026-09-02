//! ISO 10126-2 block padding.
//!
//! The last byte of the block records the padding count and the bytes before it
//! are drawn from a cryptographic generator. This is Bouncy Castle's
//! `ISO10126d2Padding`, and it is also what `X923Padding` produces once it has
//! been given a `SecureRandom`; `tc_x923_pad::X923Padding` covers the
//! zero-filled case.
//!
//! This is the one scheme in the family that needs a resource, so it is the one
//! that implements [`BlockCipherPaddingInit`](tc_pad::BlockCipherPaddingInit).
//! The generator is taken by value and kept, because every later call to
//! `add_padding` draws from it. Padding before initialization reports
//! [`PaddingError::NotInitialised`] rather than falling back to a default
//! generator the way Bouncy Castle does.
//!
//! Only the count is verified on removal. The filler is random and carries no
//! redundancy, so corruption inside it is undetectable.
//!
//! ```
//! use core::convert::Infallible;
//!
//! use rand_core::{TryCryptoRng, TryRng};
//! use tc_iso10126_pad::Iso10126Padding;
//! use tc_pad::{BlockCipherPadding, BlockCipherPaddingInit};
//!
//! // 範例用的固定產生器,只是為了讓輸出可預測。實務上請傳入真正的 CSPRNG。
//! struct ExampleRng;
//!
//! impl TryRng for ExampleRng {
//!     type Error = Infallible;
//!     fn try_next_u32(&mut self) -> Result<u32, Infallible> { Ok(0x5a5a_5a5a) }
//!     fn try_next_u64(&mut self) -> Result<u64, Infallible> { Ok(0x5a5a_5a5a_5a5a_5a5a) }
//!     fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Infallible> {
//!         output.fill(0x5a);
//!         Ok(())
//!     }
//! }
//!
//! impl TryCryptoRng for ExampleRng {}
//!
//! let mut padding = Iso10126Padding::new();
//! padding.init(ExampleRng)?;
//!
//! let mut block = [0_u8; 8];
//! block[..5].copy_from_slice(b"hello");
//! assert_eq!(padding.add_padding(&mut block, 5)?, 3);
//! assert_eq!(block, [b'h', b'e', b'l', b'l', b'o', 0x5a, 0x5a, 3]);
//!
//! assert_eq!(padding.pad_count(&block)?, 3);
//! # Ok::<(), tc_iso10126_pad::PaddingError>(())
//! ```

#![no_std]

mod padding;

pub use padding::Iso10126Padding;

// 錯誤型別由 tc_pad 共用,這裡重新匯出讓呼叫端不必額外依賴 tc_pad。
pub use tc_pad::PaddingError;
