//! ANSI X9.23 block padding.
//!
//! The last byte of the block records the padding count and the bytes before it
//! are filler. This crate writes zero filler, which is the behaviour of Bouncy
//! Castle's `X923Padding` when no `SecureRandom` is supplied.
//!
//! Bouncy Castle also lets `X923Padding` draw random filler once it is
//! initialized with a generator. That variant is a separate type here,
//! `tc_iso10126_pad::Iso10126Padding`, because random filler is exactly what
//! ISO 10126-2 specifies and the two produce interchangeable blocks. Splitting
//! them keeps the type honest about whether a generator is required: this one
//! never needs any resource, so it does not implement
//! [`BlockCipherPaddingInit`](tc_pad::BlockCipherPaddingInit).
//!
//! Only the count is verified on removal. The filler bytes are arbitrary, so
//! X9.23 cannot detect corruption inside them.
//!
//! ```
//! use tc_pad::BlockCipherPadding;
//! use tc_x923_pad::X923Padding;
//!
//! let mut padding = X923Padding::new();
//!
//! let mut block = [0xff_u8; 8];
//! block[..5].copy_from_slice(b"hello");
//! assert_eq!(padding.add_padding(&mut block, 5)?, 3);
//! assert_eq!(block, [b'h', b'e', b'l', b'l', b'o', 0, 0, 3]);
//!
//! assert_eq!(padding.pad_count(&block)?, 3);
//! # Ok::<(), tc_x923_pad::PaddingError>(())
//! ```

#![no_std]

mod padding;

pub use padding::X923Padding;

// 錯誤型別由 tc_pad 共用,這裡重新匯出讓呼叫端不必額外依賴 tc_pad。
pub use tc_pad::PaddingError;
