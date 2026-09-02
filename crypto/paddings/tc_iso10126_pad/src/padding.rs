//! ISO 10126-2 padding implementation.

use rand_core::CryptoRng;
use tc_crypto::AlgorithmName;
use tc_pad::{BlockCipherPadding, BlockCipherPaddingInit, PaddingError};

/// ISO 10126-2 padding over a single cipher block.
///
/// The generator `R` is owned by the padding because it is drawn from on every
/// call to [`add_padding`](BlockCipherPadding::add_padding). Supply it either
/// at construction with [`with_random`](Self::with_random) or later through
/// [`BlockCipherPaddingInit::init`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Iso10126Padding<R> {
    rng: Option<R>,
}

impl<R> Iso10126Padding<R> {
    /// Creates an uninitialized padding.
    ///
    /// Padding fails with [`PaddingError::NotInitialised`] until a generator is
    /// supplied through [`BlockCipherPaddingInit::init`].
    pub const fn new() -> Self {
        Self { rng: None }
    }

    /// Creates a padding that draws its filler from `rng`.
    pub const fn with_random(rng: R) -> Self {
        Self { rng: Some(rng) }
    }

    /// Consumes the padding and returns its generator, if one was supplied.
    pub fn into_inner(self) -> Option<R> {
        self.rng
    }
}

impl<R: CryptoRng> BlockCipherPaddingInit<R> for Iso10126Padding<R> {
    type Error = PaddingError;

    fn init(&mut self, params: R) -> Result<(), Self::Error> {
        self.rng = Some(params);
        Ok(())
    }
}

impl<R: CryptoRng> BlockCipherPadding for Iso10126Padding<R> {
    type Error = PaddingError;

    /// Fills `block[position..]` with random bytes and writes the padding count
    /// into the last byte of the block.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::NotInitialised`] when no generator has been
    /// supplied, [`PaddingError::PositionOutOfRange`] when `position` is past
    /// the end of the block, [`PaddingError::BlockFull`] when `position` equals
    /// the block length, since the count byte alone needs room, and
    /// [`PaddingError::UnsupportedBlockSize`] for blocks of 256 bytes or more.
    fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error> {
        if block.len() > u8::MAX as usize {
            return Err(PaddingError::UnsupportedBlockSize);
        }

        let rng = self.rng.as_mut().ok_or(PaddingError::NotInitialised)?;
        let tail = block
            .get_mut(position..)
            .ok_or(PaddingError::PositionOutOfRange)?;
        let count = tail.len();
        // split_last_mut 對空的 tail 回傳 None,正好就是「沒有位置放計數位元組」。
        let (last, filler) = tail.split_last_mut().ok_or(PaddingError::BlockFull)?;

        rng.fill_bytes(filler);
        *last = count as u8;
        Ok(count)
    }

    /// Reads the padding count from the last byte of the block.
    ///
    /// The check is the branch-free range test Bouncy Castle uses, so it runs
    /// in constant time with respect to the block contents. It needs no
    /// generator and therefore works even before initialization.
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

impl<R> AlgorithmName for Iso10126Padding<R> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("ISO10126-2")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::convert::Infallible;
    use std::string::String;
    use std::vec::Vec;

    use rand_core::{TryCryptoRng, TryRng};

    use super::Iso10126Padding;
    use tc_crypto::AlgorithmName;
    use tc_pad::{BlockCipherPadding, BlockCipherPaddingInit, PaddingError};

    /// 供給固定位元組的測試產生器,讓 padding 輸出可預測。
    struct FixedCryptoRng {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl FixedCryptoRng {
        fn new(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.to_vec(),
                offset: 0,
            }
        }

        fn take(&mut self, output: &mut [u8]) {
            let end = self.offset + output.len();
            assert!(end <= self.bytes.len(), "fixed RNG exhausted");
            output.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
        }
    }

    impl TryRng for FixedCryptoRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut output = [0_u8; 4];
            self.take(&mut output);
            Ok(u32::from_le_bytes(output))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut output = [0_u8; 8];
            self.take(&mut output);
            Ok(u64::from_le_bytes(output))
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            self.take(output);
            Ok(())
        }
    }

    impl TryCryptoRng for FixedCryptoRng {}

    #[test]
    fn fills_with_random_bytes_and_records_the_count() {
        let mut padding = Iso10126Padding::with_random(FixedCryptoRng::new(&[0x11, 0x22, 0x33]));
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 4), Ok(4));
        assert_eq!(block, [0xff, 0xff, 0xff, 0xff, 0x11, 0x22, 0x33, 4]);
        assert_eq!(padding.pad_count(&block), Ok(4));
    }

    #[test]
    fn a_single_padding_byte_draws_no_randomness() {
        // 只剩一個位元組時整格都給計數,不會向產生器要任何位元組。
        let mut padding = Iso10126Padding::with_random(FixedCryptoRng::new(&[]));
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 7), Ok(1));
        assert_eq!(block, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1]);
    }

    #[test]
    fn padding_before_initialization_is_an_error() {
        let mut padding = Iso10126Padding::<FixedCryptoRng>::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 4),
            Err(PaddingError::NotInitialised)
        );

        // pad_count 不需要產生器,未初始化也能用。
        assert_eq!(padding.pad_count(&[0xff, 0xff, 0xff, 3]), Ok(3));
    }

    #[test]
    fn init_supplies_the_generator() {
        let mut padding = Iso10126Padding::new();
        padding.init(FixedCryptoRng::new(&[0xaa, 0xbb])).unwrap();

        let mut block = [0_u8; 4];
        assert_eq!(padding.add_padding(&mut block, 1), Ok(3));
        assert_eq!(block, [0, 0xaa, 0xbb, 3]);
    }

    #[test]
    fn a_full_block_has_no_room_for_padding() {
        let mut padding = Iso10126Padding::with_random(FixedCryptoRng::new(&[]));

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 8),
            Err(PaddingError::BlockFull)
        );
    }

    #[test]
    fn rejects_a_position_past_the_end_of_the_block() {
        let mut padding = Iso10126Padding::with_random(FixedCryptoRng::new(&[]));

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 9),
            Err(PaddingError::PositionOutOfRange)
        );
    }

    #[test]
    fn rejects_blocks_too_long_for_a_single_byte_count() {
        let mut padding = Iso10126Padding::with_random(FixedCryptoRng::new(&[]));
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
        let padding = Iso10126Padding::<FixedCryptoRng>::new();

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
    fn padding_round_trips_for_every_message_length() {
        for used in 0..8 {
            let mut padding = Iso10126Padding::with_random(FixedCryptoRng::new(&[0x5a; 8]));
            let mut block = [0xa5_u8; 8];
            let added = padding.add_padding(&mut block, used).unwrap();

            assert_eq!(added, 8 - used);
            assert_eq!(padding.pad_count(&block), Ok(8 - used));
        }
    }

    #[test]
    fn reports_its_algorithm_name() {
        let mut name = String::new();
        Iso10126Padding::<FixedCryptoRng>::new()
            .write_algo_name(&mut name)
            .unwrap();
        assert_eq!(name, "ISO10126-2");
    }
}
