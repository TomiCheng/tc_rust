//! Zero-byte block padding.
//!
//! Zero-byte padding fills the unused tail of a block with `0x00`. It matches
//! Bouncy Castle's `ZeroBytePadding` and padding method 1 of ISO/IEC 9797-1.
//!
//! The scheme is *not* generally reversible: a message whose own last bytes are
//! `0x00` is indistinguishable from a shorter message followed by padding. Use
//! it only where the plaintext length is known out of band, or where the
//! plaintext is guaranteed never to end in a zero byte.
//!
//! ```
//! use tc_pad::BlockCipherPadding;
//! use tc_zero_pad::ZeroBytePadding;
//!
//! let mut padding = ZeroBytePadding::new();
//!
//! let mut block = [0_u8; 8];
//! block[..5].copy_from_slice(b"hello");
//! assert_eq!(padding.add_padding(&mut block, 5)?, 3);
//! assert_eq!(&block, b"hello\0\0\0");
//!
//! assert_eq!(padding.pad_count(&block)?, 3);
//! # Ok::<(), tc_zero_pad::PaddingError>(())
//! ```

#![no_std]

mod padding;

pub use padding::ZeroBytePadding;

// 錯誤型別由 tc_pad 共用,這裡重新匯出讓呼叫端不必額外依賴 tc_pad。
pub use tc_pad::PaddingError;
