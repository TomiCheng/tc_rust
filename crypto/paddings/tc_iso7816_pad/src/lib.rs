//! ISO 7816-4 block padding.
//!
//! Padding starts with a single `0x80` marker and continues with `0x00` to the
//! end of the block, so the count is found by locating the marker rather than
//! reading a stored length. This is Bouncy Castle's `ISO7816d4Padding`, and it
//! is padding method 2 of ISO/IEC 9797-1.
//!
//! Because the length is never encoded in a byte, this scheme places no limit
//! on the block size, and unlike zero-byte padding it stays unambiguous for
//! messages that end in `0x00`.
//!
//! ```
//! use tc_iso7816_pad::Iso7816d4Padding;
//! use tc_pad::BlockCipherPadding;
//!
//! let mut padding = Iso7816d4Padding::new();
//!
//! let mut block = [0xff_u8; 8];
//! block[..5].copy_from_slice(b"hello");
//! assert_eq!(padding.add_padding(&mut block, 5)?, 3);
//! assert_eq!(block, [b'h', b'e', b'l', b'l', b'o', 0x80, 0, 0]);
//!
//! assert_eq!(padding.pad_count(&block)?, 3);
//! # Ok::<(), tc_iso7816_pad::PaddingError>(())
//! ```

#![no_std]

mod padding;

pub use padding::Iso7816d4Padding;

// 錯誤型別由 tc_pad 共用,這裡重新匯出讓呼叫端不必額外依賴 tc_pad。
pub use tc_pad::PaddingError;
