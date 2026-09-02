//! Zero-byte padding implementation.

use tc_crypto::AlgorithmName;
use tc_pad::{BlockCipherPadding, PaddingError};

/// Zero-byte padding over a single cipher block.
///
/// The type is stateless, so one value can pad any number of blocks. It needs
/// no resources and therefore does not implement
/// [`BlockCipherPaddingInit`](tc_pad::BlockCipherPaddingInit): a freshly
/// constructed value is ready to use and never reports
/// [`PaddingError::NotInitialised`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ZeroBytePadding;

impl ZeroBytePadding {
    /// Creates a zero-byte padding.
    pub const fn new() -> Self {
        Self
    }
}

impl BlockCipherPadding for ZeroBytePadding {
    type Error = PaddingError;

    /// Fills `block[position..]` with `0x00` and returns the number of padding
    /// bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::PositionOutOfRange`] when `position` is greater
    /// than the block length. No other failure is possible.
    fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error> {
        // get_mut 對超出範圍的 range 回傳 None,順便擋掉 position > len 的呼叫端錯誤。
        let tail = block
            .get_mut(position..)
            .ok_or(PaddingError::PositionOutOfRange)?;
        tail.fill(0x00);
        Ok(tail.len())
    }

    /// Returns the number of trailing `0x00` bytes in `block`.
    ///
    /// The count is computed in constant time with respect to the block
    /// contents.
    ///
    /// # Errors
    ///
    /// None. Zero-byte padding encodes no length, so there is nothing to
    /// validate: an all-zero block reports the full block length, and a block
    /// not ending in `0x00` reports `0`.
    fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error> {
        let mut count = 0;
        // still_zero 只會是 0 或 1;為 1 表示「從尾端數到目前這個位元組都還是 0x00」。
        let mut still_zero = 1;

        for &byte in block.iter().rev() {
            // byte 為 0 時 0 - 1 借位成 usize::MAX,右移到只剩最高位得 1;
            // byte 非 0 時 byte - 1 的最高位是 0,右移後得 0。
            // 全程不分支,執行時間與資料內容無關。
            let is_zero = (byte as usize).wrapping_sub(1) >> (usize::BITS - 1);
            still_zero &= is_zero;
            count += still_zero;
        }

        Ok(count)
    }
}

impl AlgorithmName for ZeroBytePadding {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("ZeroBytePadding")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::fmt::Write;
    use std::boxed::Box;
    use std::string::String;

    use super::ZeroBytePadding;
    use tc_crypto::AlgorithmName;
    use tc_pad::{BlockCipherPadding, PaddingError};

    #[test]
    fn fills_the_tail_and_reports_the_padding_length() {
        let mut padding = ZeroBytePadding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0xff, 0xff, 0xff, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_full_block_receives_no_padding() {
        let mut padding = ZeroBytePadding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 8), Ok(0));
        assert_eq!(block, [0xff; 8]);
    }

    #[test]
    fn an_empty_block_pads_to_its_full_length() {
        let mut padding = ZeroBytePadding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 0), Ok(8));
        assert_eq!(block, [0; 8]);
    }

    #[test]
    fn rejects_a_position_past_the_end_of_the_block() {
        let mut padding = ZeroBytePadding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(
            padding.add_padding(&mut block, 9),
            Err(PaddingError::PositionOutOfRange)
        );
        assert_eq!(block, [0xff; 8]);
    }

    #[test]
    fn counts_only_trailing_zero_bytes() {
        let padding = ZeroBytePadding::new();

        // 中間的 0x00 不算,只有結尾連續的才算。
        assert_eq!(padding.pad_count(&[0x01, 0x00, 0x02, 0x00, 0x00]), Ok(2));
        assert_eq!(padding.pad_count(&[0x01, 0x02, 0x03]), Ok(0));
        assert_eq!(padding.pad_count(&[0x00; 8]), Ok(8));
        assert_eq!(padding.pad_count(&[]), Ok(0));
    }

    #[test]
    fn padding_round_trips_when_the_message_does_not_end_in_zero() {
        let mut padding = ZeroBytePadding::new();
        let message = b"hello";
        let mut block = [0xff_u8; 8];
        block[..message.len()].copy_from_slice(message);

        let added = padding.add_padding(&mut block, message.len()).unwrap();
        let recovered = block.len() - padding.pad_count(&block).unwrap();

        assert_eq!(added, 3);
        assert_eq!(&block[..recovered], message);
    }

    #[test]
    fn is_usable_without_any_initialization() {
        // 這個方案沒有未初始化狀態,所以不實作 BlockCipherPaddingInit,
        // 剛建好就能直接用,也永遠不會回報 PaddingError::NotInitialised。
        let mut padding = ZeroBytePadding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 6), Ok(2));
        assert_eq!(padding.pad_count(&block), Ok(2));
    }

    #[test]
    fn supports_dynamic_dispatch() {
        let mut padding: Box<dyn BlockCipherPadding<Error = PaddingError>> =
            Box::new(ZeroBytePadding::new());
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 5), Ok(3));
        assert_eq!(block, [0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0]);
        assert_eq!(padding.pad_count(&block), Ok(3));
    }

    #[test]
    fn reports_its_algorithm_name() {
        let mut name = String::new();
        ZeroBytePadding::new().write_algo_name(&mut name).unwrap();
        assert_eq!(name, "ZeroBytePadding");

        // AlgorithmName 走 dyn Write,確認 trait object 也能用。
        let mut sink = String::new();
        let output: &mut dyn Write = &mut sink;
        ZeroBytePadding.write_algo_name(output).unwrap();
        assert_eq!(sink, "ZeroBytePadding");
    }
}
