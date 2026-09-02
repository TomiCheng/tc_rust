//! ISO 7816-4 padding implementation.

use tc_crypto::AlgorithmName;
use tc_pad::{BlockCipherPadding, PaddingError};

/// ISO 7816-4 padding over a single cipher block.
///
/// The type is stateless, so one value can pad any number of blocks. It needs
/// no resources and therefore does not implement
/// [`BlockCipherPaddingInit`](tc_pad::BlockCipherPaddingInit).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Iso7816d4Padding;

impl Iso7816d4Padding {
    /// Creates an ISO 7816-4 padding.
    pub const fn new() -> Self {
        Self
    }
}

impl BlockCipherPadding for Iso7816d4Padding {
    type Error = PaddingError;

    /// Writes `0x80` at `position` and zeros to the end of the block.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::PositionOutOfRange`] when `position` is past the
    /// end of the block, and [`PaddingError::BlockFull`] when `position` equals
    /// the block length, since the marker byte alone needs room.
    fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error> {
        let tail = block
            .get_mut(position..)
            .ok_or(PaddingError::PositionOutOfRange)?;
        let count = tail.len();
        // split_first_mut 對空的 tail 回傳 None,正好就是「沒有位置放 0x80」。
        let (marker, rest) = tail.split_first_mut().ok_or(PaddingError::BlockFull)?;

        *marker = 0x80;
        rest.fill(0x00);
        Ok(count)
    }

    /// Locates the `0x80` marker and returns the number of bytes from it to the
    /// end of the block.
    ///
    /// The scan is the masked, branch-free walk Bouncy Castle uses: it always
    /// visits every byte, so it runs in constant time with respect to the block
    /// contents and never reveals where the marker sat.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::CorruptPadding`] when the block does not end in
    /// a `0x80` marker followed only by zeros.
    fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error> {
        // position 保持 -1 直到找到合格的標記;still_zero 為全 1 表示
        // 「從尾端走到這裡都還是 0x00」。
        let mut position: isize = -1;
        let mut still_zero: isize = -1;

        for (index, &byte) in block.iter().enumerate().rev() {
            let value = byte as isize;
            // 相等時 x ^ y 為 0,減 1 借位成 -1,最高位為 1;不相等時為 0。
            // 對 0x00 而言 value ^ 0x00 就是 value 本身,所以直接寫 value - 1。
            let matches_00 = (value - 1) >> (isize::BITS - 1);
            let matches_80 = ((value ^ 0x80) - 1) >> (isize::BITS - 1);

            // 只有「仍在尾端零串中」且「這格是 0x80」時才記下位置。
            position ^= (index as isize ^ position) & still_zero & matches_80;
            still_zero &= matches_00;
        }

        // 只在彙總結果上分支,逐位元組的掃描本身不分支。
        if position < 0 {
            return Err(PaddingError::CorruptPadding);
        }

        Ok(block.len() - position as usize)
    }
}

impl AlgorithmName for Iso7816d4Padding {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("ISO7816-4")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;

    use super::Iso7816d4Padding;
    use tc_crypto::AlgorithmName;
    use tc_pad::{BlockCipherPadding, PaddingError};

    #[test]
    fn writes_the_marker_then_zeros() {
        let mut padding = Iso7816d4Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0xff, 0xff, 0xff, 0x80, 0, 0, 0, 0]);
        assert_eq!(padding.pad_count(&block), Ok(5));
    }

    #[test]
    fn a_single_padding_byte_is_only_the_marker() {
        let mut padding = Iso7816d4Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 7), Ok(1));
        assert_eq!(block, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80]);
        assert_eq!(padding.pad_count(&block), Ok(1));
    }

    #[test]
    fn an_empty_block_pads_to_its_full_length() {
        let mut padding = Iso7816d4Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 0), Ok(8));
        assert_eq!(block, [0x80, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(padding.pad_count(&block), Ok(8));
    }

    #[test]
    fn a_full_block_has_no_room_for_padding() {
        let mut padding = Iso7816d4Padding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 8),
            Err(PaddingError::BlockFull)
        );
    }

    #[test]
    fn rejects_a_position_past_the_end_of_the_block() {
        let mut padding = Iso7816d4Padding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 9),
            Err(PaddingError::PositionOutOfRange)
        );
    }

    #[test]
    fn stays_unambiguous_for_messages_ending_in_zero() {
        let mut padding = Iso7816d4Padding::new();
        let mut block = [0x00_u8; 8];
        block[0] = 0x01;

        // 訊息是 01 00 00,結尾本身就是 0x00;標記讓它仍然可還原。
        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0x01, 0, 0, 0x80, 0, 0, 0, 0]);
        assert_eq!(padding.pad_count(&block), Ok(5));
    }

    #[test]
    fn takes_the_last_marker_when_the_message_contains_one() {
        let padding = Iso7816d4Padding::new();

        // 訊息裡的 0x80 不算,只有尾端零串前面那個才算。
        assert_eq!(padding.pad_count(&[0x80, 0x01, 0x80, 0x00]), Ok(2));
    }

    #[test]
    fn rejects_a_block_without_a_marker() {
        let padding = Iso7816d4Padding::new();

        assert_eq!(
            padding.pad_count(&[1, 2, 3, 4]),
            Err(PaddingError::CorruptPadding)
        );
        // 全零沒有標記。
        assert_eq!(
            padding.pad_count(&[0, 0, 0, 0]),
            Err(PaddingError::CorruptPadding)
        );
        assert_eq!(padding.pad_count(&[]), Err(PaddingError::CorruptPadding));
    }

    #[test]
    fn padding_round_trips_for_every_message_length() {
        let mut padding = Iso7816d4Padding::new();

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
        Iso7816d4Padding::new().write_algo_name(&mut name).unwrap();
        assert_eq!(name, "ISO7816-4");
    }
}
