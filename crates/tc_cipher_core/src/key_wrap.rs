//! Key-wrapping contracts.

/// The operation selected during key-wrapper initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapDirection {
    /// Protect key material and produce a wrapped blob.
    Wrap,
    /// Recover and authenticate key material from a wrapped blob.
    Unwrap,
}

/// An initialized key-wrapping algorithm.
///
/// This trait uses caller-provided output buffers, so the contract itself needs
/// neither `alloc` nor `std`. Initialization is provided separately by
/// [`KeyWrapInit`], whose generic associated parameter type is intentionally
/// kept out of this trait.
///
/// Implementations with the same [`Error`](KeyWrap::Error) type can be stored
/// behind `dyn KeyWrap<Error = E>` after they have been initialized.
pub trait KeyWrap {
    /// The failure type returned by sizing and key-wrapping operations.
    type Error: core::error::Error;

    /// Returns the algorithm name.
    fn algorithm_name(&self) -> &str;

    /// Returns the exact output length required to wrap `input_len` bytes.
    ///
    /// Invalid input lengths and arithmetic overflow must be reported as an
    /// error rather than being deferred to [`wrap_into`](KeyWrap::wrap_into).
    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error>;

    /// Returns an output capacity sufficient to unwrap `input_len` bytes.
    ///
    /// Some formats encode the original key length inside the authenticated
    /// wrapped blob, so the exact length is unavailable before unwrapping. The
    /// successful return value from [`unwrap_into`](KeyWrap::unwrap_into)
    /// reports how many bytes were actually written.
    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error>;

    /// Wraps `input` into `output` and returns the number of bytes written.
    ///
    /// `output` must have at least the capacity reported by
    /// [`wrapped_len`](KeyWrap::wrapped_len) for this input length.
    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Unwraps and authenticates `input` into `output`, returning the number of
    /// recovered key bytes written.
    ///
    /// `output` must have at least the capacity reported by
    /// [`max_unwrapped_len`](KeyWrap::max_unwrapped_len). Implementations must
    /// not leave recovered, unauthenticated key material in `output` when an
    /// integrity check fails.
    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Strongly typed initialization for a [`KeyWrap`] implementation.
///
/// The generic associated type permits parameter objects that borrow key, IV,
/// or other initialization material. Because that GAT is not part of
/// [`KeyWrap`], initialized implementations can still be used through
/// `dyn KeyWrap`.
pub trait KeyWrapInit: KeyWrap {
    /// The parameter type accepted by [`init`](KeyWrapInit::init).
    type Params<'a>;

    /// Initializes the implementation for wrapping or unwrapping.
    fn init(
        &mut self,
        direction: WrapDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::fmt;
    use std::boxed::Box;

    use super::{KeyWrap, KeyWrapInit, WrapDirection};

    #[derive(Debug, PartialEq, Eq)]
    enum TestError {
        Uninitialised,
        WrongDirection,
        InvalidInputLength,
        OutputTooShort,
        IntegrityCheckFailed,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(match self {
                Self::Uninitialised => "key wrapper not initialised",
                Self::WrongDirection => "key wrapper initialised for the other direction",
                Self::InvalidInputLength => "invalid input length",
                Self::OutputTooShort => "output buffer is too short",
                Self::IntegrityCheckFailed => "integrity check failed",
            })
        }
    }

    impl core::error::Error for TestError {}

    struct TestParams<'a> {
        key: &'a [u8],
    }

    #[derive(Default)]
    struct TestKeyWrap {
        direction: Option<WrapDirection>,
        mask: u8,
    }

    impl KeyWrap for TestKeyWrap {
        type Error = TestError;

        fn algorithm_name(&self) -> &str {
            "TestKeyWrap"
        }

        fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
            input_len
                .checked_add(1)
                .ok_or(TestError::InvalidInputLength)
        }

        fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
            input_len
                .checked_sub(1)
                .ok_or(TestError::InvalidInputLength)
        }

        fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            match self.direction {
                None => return Err(TestError::Uninitialised),
                Some(WrapDirection::Unwrap) => return Err(TestError::WrongDirection),
                Some(WrapDirection::Wrap) => {}
            }

            let required = self.wrapped_len(input.len())?;
            if output.len() < required {
                return Err(TestError::OutputTooShort);
            }

            let checksum = input.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
            for (input, output) in input.iter().zip(output.iter_mut()) {
                *output = *input ^ self.mask;
            }
            output[input.len()] = checksum ^ self.mask;
            Ok(required)
        }

        fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            match self.direction {
                None => return Err(TestError::Uninitialised),
                Some(WrapDirection::Wrap) => return Err(TestError::WrongDirection),
                Some(WrapDirection::Unwrap) => {}
            }

            let required = self.max_unwrapped_len(input.len())?;
            if output.len() < required {
                return Err(TestError::OutputTooShort);
            }

            let (body, trailer) = input.split_at(required);
            let checksum = body
                .iter()
                .fold(0_u8, |sum, byte| sum.wrapping_add(*byte ^ self.mask));
            if trailer[0] ^ self.mask != checksum {
                return Err(TestError::IntegrityCheckFailed);
            }

            for (input, output) in body.iter().zip(output.iter_mut()) {
                *output = *input ^ self.mask;
            }
            Ok(required)
        }
    }

    impl KeyWrapInit for TestKeyWrap {
        type Params<'a> = TestParams<'a>;

        fn init(
            &mut self,
            direction: WrapDirection,
            params: &Self::Params<'_>,
        ) -> Result<(), Self::Error> {
            self.mask = params.key.first().copied().unwrap_or(0);
            self.direction = Some(direction);
            Ok(())
        }
    }

    #[test]
    fn initialized_operations_support_dynamic_dispatch() {
        let params = TestParams { key: &[0x5a] };
        let plaintext = [0x11, 0x22, 0x33, 0x44];

        let mut concrete = TestKeyWrap::default();
        concrete.init(WrapDirection::Wrap, &params).unwrap();
        let mut wrapper: Box<dyn KeyWrap<Error = TestError>> = Box::new(concrete);
        let mut wrapped = [0_u8; 5];

        assert_eq!(wrapper.algorithm_name(), "TestKeyWrap");
        assert_eq!(wrapper.wrapped_len(plaintext.len()), Ok(5));
        assert_eq!(wrapper.wrap_into(&plaintext, &mut wrapped), Ok(5));

        let mut concrete = TestKeyWrap::default();
        concrete.init(WrapDirection::Unwrap, &params).unwrap();
        let mut unwrapper: Box<dyn KeyWrap<Error = TestError>> = Box::new(concrete);
        let mut recovered = [0_u8; 4];

        assert_eq!(unwrapper.max_unwrapped_len(wrapped.len()), Ok(4));
        assert_eq!(unwrapper.unwrap_into(&wrapped, &mut recovered), Ok(4));
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn integrity_failure_does_not_expose_unauthenticated_output() {
        let params = TestParams { key: &[0x5a] };
        let mut unwrapper = TestKeyWrap::default();
        unwrapper.init(WrapDirection::Unwrap, &params).unwrap();

        let tampered = [0x4b, 0x78, 0x69, 0x1e, 0x00];
        let mut output = [0xa5_u8; 4];

        assert_eq!(
            unwrapper.unwrap_into(&tampered, &mut output),
            Err(TestError::IntegrityCheckFailed)
        );
        assert_eq!(output, [0xa5; 4]);
    }
}
