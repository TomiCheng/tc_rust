//! Block-cipher padding contract.

/// A padding scheme applied to the final block of a block-cipher message.
///
/// This is the port of Bouncy Castle's `IBlockCipherPadding`, with two
/// deliberate differences:
///
/// * `PaddingName` is not part of this trait. Schemes report their name by
///   implementing `tc_crypto::AlgorithmName`, which keeps this crate free of
///   dependencies in the same way as the other shared trait crates.
/// * `Init(SecureRandom)` lives on the separate [`BlockCipherPaddingInit`]
///   trait, matching how `tc_cipher` and `tc_macs` keep initialization apart
///   from the operations that a trait object exposes.
///
/// The trait contains only operations that can be dispatched through a trait
/// object, so implementations with the same
/// [`Error`](BlockCipherPadding::Error) type can be stored together behind
/// `dyn BlockCipherPadding<Error = E>`.
pub trait BlockCipherPadding {
    /// The failure type returned by padding operations.
    type Error: core::error::Error;

    /// Pads `block[position..]` and returns the number of padding bytes added.
    ///
    /// `block` is one complete cipher block whose first `position` bytes hold
    /// the remaining message. Implementations overwrite every byte from
    /// `position` to the end of the block, so a `position` equal to the block
    /// length adds no bytes and leaves the block unchanged.
    ///
    /// The receiver is mutable because schemes that draw padding from a random
    /// generator advance that generator here.
    ///
    /// # Errors
    ///
    /// Returns an error when `position` is greater than the block length.
    fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error>;

    /// Returns the number of padding bytes at the end of `block`.
    ///
    /// The message occupies `block.len() - pad_count(block)` bytes. Callers
    /// must treat the result as untrusted length information until the message
    /// itself has been authenticated.
    ///
    /// # Errors
    ///
    /// Self-describing schemes return an error when the trailing bytes are not
    /// a valid encoding. Schemes that encode no length always succeed.
    fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error>;
}

/// Initializes a padding scheme from parameters of type `P`.
///
/// This is the port of `IBlockCipherPadding.Init(SecureRandom)`. It is
/// independent from [`BlockCipherPadding`]; consumers that need both use
/// `S: BlockCipherPadding + BlockCipherPaddingInit<P>`.
///
/// `P` is taken by value because a randomized scheme such as ISO 10126-2 keeps
/// using its generator on every later `add_padding` call and therefore has to
/// own it. Callers that want to keep their generator pass `&mut rng`, which
/// `rand_core` also implements the generator traits for. Schemes that need
/// nothing, such as zero-byte padding, accept any `P` and ignore it, mirroring
/// the Bouncy Castle implementations that discard the `SecureRandom`.
pub trait BlockCipherPaddingInit<P> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the padding scheme with the supplied parameters.
    fn init(&mut self, params: P) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::boxed::Box;

    use super::{BlockCipherPadding, BlockCipherPaddingInit};
    use crate::PaddingError;

    /// 需要先 init 才能使用的最小 padding:用 init 交進來的位元組填滿尾端。
    /// 形態刻意比照 ISO 10126-2 這種「先拿到資源,之後每次 add_padding 都會用到」的方案。
    #[derive(Default)]
    struct TestPadding {
        filler: Option<u8>,
    }

    impl BlockCipherPaddingInit<u8> for TestPadding {
        type Error = PaddingError;

        fn init(&mut self, params: u8) -> Result<(), Self::Error> {
            self.filler = Some(params);
            Ok(())
        }
    }

    impl BlockCipherPadding for TestPadding {
        type Error = PaddingError;

        fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error> {
            let filler = self.filler.ok_or(PaddingError::NotInitialised)?;
            let tail = block
                .get_mut(position..)
                .ok_or(PaddingError::PositionOutOfRange)?;
            tail.fill(filler);
            Ok(tail.len())
        }

        fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error> {
            let filler = self.filler.ok_or(PaddingError::NotInitialised)?;
            let count = block
                .iter()
                .rev()
                .take_while(|&&byte| byte == filler)
                .count();
            if count == 0 {
                return Err(PaddingError::CorruptPadding);
            }
            Ok(count)
        }
    }

    #[test]
    fn initialization_and_padding_support_dynamic_dispatch() {
        let mut concrete = TestPadding::default();
        let initializer: &mut dyn BlockCipherPaddingInit<u8, Error = PaddingError> = &mut concrete;
        initializer.init(0xa5).unwrap();

        let mut padding: Box<dyn BlockCipherPadding<Error = PaddingError>> = Box::new(concrete);
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 5), Ok(3));
        assert_eq!(block, [0xff, 0xff, 0xff, 0xff, 0xff, 0xa5, 0xa5, 0xa5]);
        assert_eq!(padding.pad_count(&block), Ok(3));
    }

    #[test]
    fn using_a_scheme_before_initialization_is_an_error() {
        let mut padding = TestPadding::default();

        assert_eq!(
            padding.add_padding(&mut [0_u8; 8], 5),
            Err(PaddingError::NotInitialised)
        );
        assert_eq!(
            padding.pad_count(&[0_u8; 8]),
            Err(PaddingError::NotInitialised)
        );
    }

    #[test]
    fn a_position_past_the_block_is_rejected() {
        let mut padding = TestPadding::default();
        padding.init(0xa5).unwrap();

        assert_eq!(
            padding.add_padding(&mut [0_u8; 8], 9),
            Err(PaddingError::PositionOutOfRange)
        );
    }

    #[test]
    fn self_describing_schemes_can_report_corruption() {
        let mut padding = TestPadding::default();
        padding.init(0xa5).unwrap();

        assert_eq!(
            padding.pad_count(&[1, 2, 3, 4]),
            Err(PaddingError::CorruptPadding)
        );
        assert_eq!(padding.pad_count(&[]), Err(PaddingError::CorruptPadding));
    }
}
