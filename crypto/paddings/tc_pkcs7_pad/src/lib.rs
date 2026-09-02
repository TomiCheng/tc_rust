//! PKCS#7 block padding.
//!
//! Every padding byte carries the number of bytes added, so the count can be
//! recovered from the block alone and verified. This matches Bouncy Castle's
//! `Pkcs7Padding`, and for eight-byte blocks it is the padding of PKCS#5.
//!
//! The count is stored in a single byte, so blocks of 256 bytes or more are
//! rejected with [`PaddingError::UnsupportedBlockSize`].
//!
//! ```
//! use tc_pad::BlockCipherPadding;
//! use tc_pkcs7_pad::Pkcs7Padding;
//!
//! let mut padding = Pkcs7Padding::new();
//!
//! let mut block = [0_u8; 8];
//! block[..5].copy_from_slice(b"hello");
//! assert_eq!(padding.add_padding(&mut block, 5)?, 3);
//! assert_eq!(block, [b'h', b'e', b'l', b'l', b'o', 3, 3, 3]);
//!
//! assert_eq!(padding.pad_count(&block)?, 3);
//! # Ok::<(), tc_pkcs7_pad::PaddingError>(())
//! ```

#![no_std]

mod padding;

pub use padding::Pkcs7Padding;

// 錯誤型別由 tc_pad 共用,這裡重新匯出讓呼叫端不必額外依賴 tc_pad。
pub use tc_pad::PaddingError;
