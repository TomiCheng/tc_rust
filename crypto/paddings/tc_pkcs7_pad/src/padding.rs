//! PKCS#7 padding implementation.

use tc_crypto::AlgorithmName;
use tc_pad::{BlockCipherPadding, PaddingError};

/// PKCS#7 padding over a single cipher block.
///
/// The type is stateless, so one value can pad any number of blocks. It needs
/// no resources and therefore does not implement
/// [`BlockCipherPaddingInit`](tc_pad::BlockCipherPaddingInit).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pkcs7Padding;

impl Pkcs7Padding {
    /// Creates a PKCS#7 padding.
    pub const fn new() -> Self {
        Self
    }
}

impl BlockCipherPadding for Pkcs7Padding {
    type Error = PaddingError;

    /// Writes the padding count into every byte of `block[position..]`.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::PositionOutOfRange`] when `position` is past the
    /// end of the block, [`PaddingError::BlockFull`] when `position` equals the
    /// block length, since PKCS#7 must add at least one byte, and
    /// [`PaddingError::UnsupportedBlockSize`] for blocks of 256 bytes or more.
    fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error> {
        if block.len() > u8::MAX as usize {
            return Err(PaddingError::UnsupportedBlockSize);
        }

        let tail = block
            .get_mut(position..)
            .ok_or(PaddingError::PositionOutOfRange)?;
        let count = tail.len();
        if count == 0 {
            return Err(PaddingError::BlockFull);
        }

        tail.fill(count as u8);
        Ok(count)
    }

    /// Reads the padding count from the last byte and verifies every padding
    /// byte against it.
    ///
    /// The verification is the masked, branch-free comparison Bouncy Castle
    /// uses, so it runs in constant time with respect to the block contents:
    /// a rejected block reveals only that it was rejected, never how far the
    /// comparison got.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::CorruptPadding`] when the block is empty, when
    /// the recorded count is zero or longer than the block, or when any byte in
    /// the padding region disagrees with it.
    fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error> {
        if block.len() > u8::MAX as usize {
            return Err(PaddingError::UnsupportedBlockSize);
        }

        let last = *block.last().ok_or(PaddingError::CorruptPadding)?;
        let count = last as isize;
        // position 是 padding 的起點。count 為 0 時 count - 1 是 -1,
        // count 大於區塊長度時 position 是負數,兩者最高位都會是 1。
        let position = block.len() as isize - count;
        let mut failed = (position | (count - 1)) >> (isize::BITS - 1);

        for (index, &byte) in block.iter().enumerate() {
            // index >= position 時遮罩為全 1(要比對),否則為 0(略過)。
            let in_padding = !((index as isize - position) >> (isize::BITS - 1));
            failed |= (byte ^ last) as isize & in_padding;
        }

        // 只在彙總結果上分支,逐位元組的比對本身不分支。
        if failed != 0 {
            return Err(PaddingError::CorruptPadding);
        }

        Ok(count as usize)
    }
}

impl AlgorithmName for Pkcs7Padding {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("PKCS7")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;

    use super::Pkcs7Padding;
    use tc_crypto::AlgorithmName;
    use tc_pad::{BlockCipherPadding, PaddingError};

    #[test]
    fn writes_the_count_into_every_padding_byte() {
        let mut padding = Pkcs7Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0xff, 0xff, 0xff, 5, 5, 5, 5, 5]);
        assert_eq!(padding.pad_count(&block), Ok(5));
    }

    #[test]
    fn an_empty_block_pads_to_its_full_length() {
        let mut padding = Pkcs7Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 0), Ok(8));
        assert_eq!(block, [8; 8]);
        assert_eq!(padding.pad_count(&block), Ok(8));
    }

    #[test]
    fn a_full_block_has_no_room_for_padding() {
        let mut padding = Pkcs7Padding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 8),
            Err(PaddingError::BlockFull)
        );
    }

    #[test]
    fn rejects_a_position_past_the_end_of_the_block() {
        let mut padding = Pkcs7Padding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 9),
            Err(PaddingError::PositionOutOfRange)
        );
    }

    #[test]
    fn rejects_blocks_too_long_for_a_single_byte_count() {
        let mut padding = Pkcs7Padding::new();
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
    fn rejects_corrupt_padding() {
        let padding = Pkcs7Padding::new();

        // 計數為 0。
        assert_eq!(
            padding.pad_count(&[1, 2, 3, 0]),
            Err(PaddingError::CorruptPadding)
        );
        // 計數超過區塊長度。
        assert_eq!(
            padding.pad_count(&[1, 2, 3, 9]),
            Err(PaddingError::CorruptPadding)
        );
        // padding 區內有位元組跟計數不一致。
        assert_eq!(
            padding.pad_count(&[1, 3, 2, 3]),
            Err(PaddingError::CorruptPadding)
        );
        // 空區塊。
        assert_eq!(padding.pad_count(&[]), Err(PaddingError::CorruptPadding));
    }

    #[test]
    fn padding_round_trips_for_every_message_length() {
        let mut padding = Pkcs7Padding::new();

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
        Pkcs7Padding::new().write_algo_name(&mut name).unwrap();
        assert_eq!(name, "PKCS7");
    }
}
