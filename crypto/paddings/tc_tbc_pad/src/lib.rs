//! Trailing bit complement (TBC) block padding.
//!
//! The padding byte is the complement of the message's last bit: a message
//! ending in a `0` bit is padded with `0xff`, and one ending in a `1` bit with
//! `0x00`. Removal counts the trailing run of that byte. This is Bouncy
//! Castle's `TbcPadding`.
//!
//! Because the pad byte always disagrees with the message's last bit, the run
//! cannot reach into the message, so no length has to be stored and no block
//! size limit applies.
//!
//! ```
//! use tc_pad::BlockCipherPadding;
//! use tc_tbc_pad::TbcPadding;
//!
//! let mut padding = TbcPadding::new();
//!
//! let mut block = [0_u8; 8];
//! block[..5].copy_from_slice(b"hello");
//! // 'o' 是 0x6f,最後一個位元為 1,所以補 0x00。
//! assert_eq!(padding.add_padding(&mut block, 5)?, 3);
//! assert_eq!(block, [b'h', b'e', b'l', b'l', b'o', 0, 0, 0]);
//!
//! assert_eq!(padding.pad_count(&block)?, 3);
//! # Ok::<(), tc_tbc_pad::PaddingError>(())
//! ```

#![no_std]

mod padding;

pub use padding::TbcPadding;

// 錯誤型別由 tc_pad 共用,這裡重新匯出讓呼叫端不必額外依賴 tc_pad。
pub use tc_pad::PaddingError;
