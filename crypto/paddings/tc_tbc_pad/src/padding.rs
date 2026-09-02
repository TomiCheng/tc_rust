//! Trailing bit complement padding implementation.

use tc_crypto::AlgorithmName;
use tc_pad::{BlockCipherPadding, PaddingError};

/// Trailing bit complement padding over a single cipher block.
///
/// The type is stateless, so one value can pad any number of blocks. It needs
/// no resources and therefore does not implement
/// [`BlockCipherPaddingInit`](tc_pad::BlockCipherPaddingInit).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TbcPadding;

impl TbcPadding {
    /// Creates a trailing bit complement padding.
    pub const fn new() -> Self {
        Self
    }
}

impl BlockCipherPadding for TbcPadding {
    type Error = PaddingError;

    /// Fills `block[position..]` with the complement of the message's last bit.
    ///
    /// When `position` is zero the whole block is padding and there is no
    /// message byte in it to look at. Bouncy Castle then reads the block's own
    /// last byte, which still holds whatever the caller left there, and this
    /// port keeps that behaviour so both produce the same block.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::PositionOutOfRange`] when `position` is past the
    /// end of the block, and [`PaddingError::BlockFull`] when `position` equals
    /// the block length, since TBC must add at least one byte.
    fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error> {
        let count = block
            .len()
            .checked_sub(position)
            .ok_or(PaddingError::PositionOutOfRange)?;
        if count == 0 {
            return Err(PaddingError::BlockFull);
        }

        // 取「訊息的最後一個位元組」。整格都是 padding 時沒有這個位元組,
        // 照 BC 的作法退而讀區塊自己的最後一格。
        let last = if position > 0 {
            block[position - 1]
        } else {
            block[block.len() - 1]
        };
        let code = if last & 0x01 == 0 { 0xff } else { 0x00 };

        block[position..].fill(code);
        Ok(count)
    }

    /// Counts the trailing run of bytes equal to the block's last byte.
    ///
    /// Bouncy Castle stops its loop as soon as the run ends. This port instead
    /// walks every byte with the same masked, branch-free scan used for
    /// zero-byte padding, so the count runs in constant time with respect to
    /// the block contents while producing the same result.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::CorruptPadding`] when the block is empty.
    fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error> {
        let code = *block.last().ok_or(PaddingError::CorruptPadding)?;

        let mut count = 0;
        // still_run 只會是 0 或 1;為 1 表示「從尾端數到這裡都還等於 code」。
        let mut still_run = 1;

        for &byte in block.iter().rev() {
            // 相等時 byte ^ code 為 0,減 1 借位成 usize::MAX,右移後得 1。
            let matches = ((byte ^ code) as usize).wrapping_sub(1) >> (usize::BITS - 1);
            still_run &= matches;
            count += still_run;
        }

        Ok(count)
    }
}

impl AlgorithmName for TbcPadding {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("TBC")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;

    use super::TbcPadding;
    use tc_crypto::AlgorithmName;
    use tc_pad::{BlockCipherPadding, PaddingError};

    #[test]
    fn a_message_ending_in_a_zero_bit_is_padded_with_ones() {
        let mut padding = TbcPadding::new();
        let mut block = [0x11_u8; 8];
        block[2] = 0x1e; // 最後一個位元為 0

        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0x11, 0x11, 0x1e, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(padding.pad_count(&block), Ok(5));
    }

    #[test]
    fn a_message_ending_in_a_one_bit_is_padded_with_zeros() {
        let mut padding = TbcPadding::new();
        let mut block = [0x11_u8; 8];
        block[2] = 0x1f; // 最後一個位元為 1

        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0x11, 0x11, 0x1f, 0, 0, 0, 0, 0]);
        assert_eq!(padding.pad_count(&block), Ok(5));
    }

    #[test]
    fn the_run_never_reaches_into_the_message() {
        let mut padding = TbcPadding::new();

        // 訊息最後一格是 0xfe(末位為 0),補 0xff;兩者不同,所以計數停在正確位置。
        let mut block = [0xfe_u8; 8];
        assert_eq!(padding.add_padding(&mut block, 4), Ok(4));
        assert_eq!(block, [0xfe, 0xfe, 0xfe, 0xfe, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(padding.pad_count(&block), Ok(4));
    }

    #[test]
    fn a_single_padding_byte_is_recovered() {
        let mut padding = TbcPadding::new();
        let mut block = [0x1f_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 7), Ok(1));
        assert_eq!(block, [0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0]);
        assert_eq!(padding.pad_count(&block), Ok(1));
    }

    #[test]
    fn a_whole_block_of_padding_uses_the_blocks_own_last_byte() {
        let mut padding = TbcPadding::new();

        // position 為 0 時沒有訊息位元組可看,照 BC 讀區塊最後一格 0x1e(末位為 0)。
        let mut block = [0x1e_u8; 8];
        assert_eq!(padding.add_padding(&mut block, 0), Ok(8));
        assert_eq!(block, [0xff; 8]);
        assert_eq!(padding.pad_count(&block), Ok(8));
    }

    #[test]
    fn a_full_block_has_no_room_for_padding() {
        let mut padding = TbcPadding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 8),
            Err(PaddingError::BlockFull)
        );
    }

    #[test]
    fn rejects_a_position_past_the_end_of_the_block() {
        let mut padding = TbcPadding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 9),
            Err(PaddingError::PositionOutOfRange)
        );
    }

    #[test]
    fn rejects_an_empty_block() {
        let padding = TbcPadding::new();

        assert_eq!(padding.pad_count(&[]), Err(PaddingError::CorruptPadding));
    }

    #[test]
    fn padding_round_trips_for_every_message_length() {
        let mut padding = TbcPadding::new();

        for used in 1..8 {
            let mut block = [0xa5_u8; 8];
            let added = padding.add_padding(&mut block, used).unwrap();

            assert_eq!(added, 8 - used);
            assert_eq!(padding.pad_count(&block), Ok(8 - used));
        }
    }

    #[test]
    fn reports_its_algorithm_name() {
        let mut name = String::new();
        TbcPadding::new().write_algo_name(&mut name).unwrap();
        assert_eq!(name, "TBC");
    }
}
