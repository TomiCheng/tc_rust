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
/// This trait uses caller-provided output buffers, so the contract itself
/// requires neither `alloc` nor `std`. Initialization is provided independently
/// by [`KeyWrapInit`].
///
/// Implementations with the same [`Error`](KeyWrap::Error) type can be stored
/// behind `dyn KeyWrap<Error = E>` after initialization.
pub trait KeyWrap {
    /// The failure type returned by sizing and key-wrapping operations.
    type Error: core::error::Error;

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

/// Initializes a key wrapper from parameters of type `P`.
///
/// This trait is independent from [`KeyWrap`]. Consumers that need both
/// capabilities use `W: KeyWrap + KeyWrapInit<P>`. Keeping `P` as a trait
/// parameter lets one caller-owned parameter object flow through composing
/// cryptographic layers.
pub trait KeyWrapInit<P: ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the implementation for wrapping or unwrapping.
    fn init(&mut self, direction: WrapDirection, params: &P) -> Result<(), Self::Error>;
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

    #[derive(Debug, PartialEq, Eq)]
    struct TestInitError;

    impl fmt::Display for TestInitError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("key must not be empty")
        }
    }

    impl core::error::Error for TestInitError {}

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

    impl KeyWrapInit<TestParams<'_>> for TestKeyWrap {
        type Error = TestInitError;

        fn init(
            &mut self,
            direction: WrapDirection,
            params: &TestParams<'_>,
        ) -> Result<(), Self::Error> {
            self.mask = params.key.first().copied().ok_or(TestInitError)?;
            self.direction = Some(direction);
            Ok(())
        }
    }

    #[test]
    fn initialization_and_operations_support_dynamic_dispatch() {
        let params = TestParams { key: &[0x5a] };
        let plaintext = [0x11, 0x22, 0x33, 0x44];

        let mut concrete = TestKeyWrap::default();
        let initializer: &mut dyn KeyWrapInit<TestParams<'_>, Error = TestInitError> =
            &mut concrete;
        initializer.init(WrapDirection::Wrap, &params).unwrap();
        let mut wrapper: Box<dyn KeyWrap<Error = TestError>> = Box::new(concrete);
        let mut wrapped = [0_u8; 5];

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
    fn initialization_has_an_independent_error_type() {
        let mut wrapper = TestKeyWrap::default();
        assert_eq!(
            wrapper.init(WrapDirection::Wrap, &TestParams { key: &[] }),
            Err(TestInitError)
        );
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
