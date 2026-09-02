//! ANSI X9.23 padding implementation.

use tc_crypto::AlgorithmName;
use tc_pad::{BlockCipherPadding, PaddingError};

/// ANSI X9.23 padding with zero filler, over a single cipher block.
///
/// The type is stateless, so one value can pad any number of blocks. It needs
/// no resources and therefore does not implement
/// [`BlockCipherPaddingInit`](tc_pad::BlockCipherPaddingInit).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X923Padding;

impl X923Padding {
    /// Creates an X9.23 padding.
    pub const fn new() -> Self {
        Self
    }
}

impl BlockCipherPadding for X923Padding {
    type Error = PaddingError;

    /// Zero-fills `block[position..]` and writes the padding count into the
    /// last byte of the block.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::PositionOutOfRange`] when `position` is past the
    /// end of the block, [`PaddingError::BlockFull`] when `position` equals the
    /// block length, since the count byte alone needs room, and
    /// [`PaddingError::UnsupportedBlockSize`] for blocks of 256 bytes or more.
    fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error> {
        if block.len() > u8::MAX as usize {
            return Err(PaddingError::UnsupportedBlockSize);
        }

        let tail = block
            .get_mut(position..)
            .ok_or(PaddingError::PositionOutOfRange)?;
        let count = tail.len();
        // split_last_mut 對空的 tail 回傳 None,正好就是「沒有位置放計數位元組」。
        let (last, filler) = tail.split_last_mut().ok_or(PaddingError::BlockFull)?;

        filler.fill(0x00);
        *last = count as u8;
        Ok(count)
    }

    /// Reads the padding count from the last byte of the block.
    ///
    /// The check is the branch-free range test Bouncy Castle uses, so it runs
    /// in constant time with respect to the block contents. Only the count is
    /// verified: X9.23 filler is arbitrary and carries no redundancy, so
    /// corruption inside it is undetectable.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::CorruptPadding`] when the block is empty or when
    /// the recorded count is zero or longer than the block.
    fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error> {
        if block.len() > u8::MAX as usize {
            return Err(PaddingError::UnsupportedBlockSize);
        }

        let count = *block.last().ok_or(PaddingError::CorruptPadding)? as isize;
        // count 為 0 時 count - 1 是 -1;count 大於區塊長度時 position 是負數。
        let position = block.len() as isize - count;
        let failed = (position | (count - 1)) >> (isize::BITS - 1);

        if failed != 0 {
            return Err(PaddingError::CorruptPadding);
        }

        Ok(count as usize)
    }
}

impl AlgorithmName for X923Padding {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("X9.23")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;

    use super::X923Padding;
    use tc_crypto::AlgorithmName;
    use tc_pad::{BlockCipherPadding, PaddingError};

    #[test]
    fn zero_fills_and_records_the_count_in_the_last_byte() {
        let mut padding = X923Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0xff, 0xff, 0xff, 0, 0, 0, 0, 5]);
        assert_eq!(padding.pad_count(&block), Ok(5));
    }

    #[test]
    fn a_single_padding_byte_is_only_the_count() {
        let mut padding = X923Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 7), Ok(1));
        assert_eq!(block, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1]);
        assert_eq!(padding.pad_count(&block), Ok(1));
    }

    #[test]
    fn an_empty_block_pads_to_its_full_length() {
        let mut padding = X923Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 0), Ok(8));
        assert_eq!(block, [0, 0, 0, 0, 0, 0, 0, 8]);
        assert_eq!(padding.pad_count(&block), Ok(8));
    }

    #[test]
    fn a_full_block_has_no_room_for_padding() {
        let mut padding = X923Padding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 8),
            Err(PaddingError::BlockFull)
        );
    }

    #[test]
    fn rejects_a_position_past_the_end_of_the_block() {
        let mut padding = X923Padding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 9),
            Err(PaddingError::PositionOutOfRange)
        );
    }

    #[test]
    fn rejects_blocks_too_long_for_a_single_byte_count() {
        let mut padding = X923Padding::new();
        let mut block = [0_u8; 256];

        assert_eq!(
            padding.add_padding(&mut block, 0),
            Err(PaddingError::UnsupportedBlockSize)
        );
        assert_eq!(
            padding.pad_count(&block),
            Err(PaddingError::UnsupportedBlockSize)
        );
    }

    #[test]
    fn rejects_an_out_of_range_count() {
        let padding = X923Padding::new();

        assert_eq!(
            padding.pad_count(&[1, 2, 3, 0]),
            Err(PaddingError::CorruptPadding)
        );
        assert_eq!(
            padding.pad_count(&[1, 2, 3, 9]),
            Err(PaddingError::CorruptPadding)
        );
        assert_eq!(padding.pad_count(&[]), Err(PaddingError::CorruptPadding));
    }

    #[test]
    fn filler_corruption_is_undetectable() {
        let padding = X923Padding::new();

        // 只有計數位元組被驗證,填充內容任意,所以這仍然是「合法」的 X9.23 區塊。
        assert_eq!(padding.pad_count(&[1, 2, 0xaa, 0xbb, 3]), Ok(3));
    }

    #[test]
    fn padding_round_trips_for_every_message_length() {
        let mut padding = X923Padding::new();

        for used in 0..8 {
            let mut block = [0xa5_u8; 8];
            let added = padding.add_padding(&mut block, used).unwrap();

            assert_eq!(added, 8 - used);
            assert_eq!(padding.pad_count(&block), Ok(8 - used));
        }
    }

    #[test]
    fn reports_its_algorithm_name() {
        let mut name = String::new();
        X923Padding::new().write_algo_name(&mut name).unwrap();
        assert_eq!(name, "X9.23");
    }
}
