//! Message-authentication-code contracts.

/// An initialized streaming message authentication code.
///
/// This trait contains only operations that can be dispatched through a trait
/// object. Initialization is provided independently by [`MacInit`].
///
/// Implementations with the same [`Error`](Mac::Error) type can be stored
/// together behind `dyn Mac<Error = E>` after initialization.
pub trait Mac {
    /// The failure type returned by MAC operations.
    type Error: core::error::Error;

    /// Returns the authentication-tag size in bytes.
    fn mac_size(&self) -> usize;

    /// Adds message bytes to the authentication calculation.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Finalizes the authentication calculation into `output`.
    ///
    /// Returns the number of bytes written, which is normally
    /// [`mac_size`](Mac::mac_size). A successful call resets the accumulated
    /// message state while retaining the state established by the most recent
    /// initialization.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Clears the accumulated message and restores the state established by
    /// the most recent initialization.
    fn reset(&mut self);
}

/// Initializes a message authentication code from parameters of type `P`.
///
/// This trait is independent from [`Mac`]. Consumers that need both
/// capabilities use `M: Mac + MacInit<P>`. Keeping `P` as a trait parameter
/// lets one caller-owned parameter object flow through composing cryptographic
/// layers.
pub trait MacInit<P: ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the MAC with the supplied parameters.
    fn init(&mut self, params: &P) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::fmt;

    use super::{Mac, MacInit};

    trait TestParams {
        fn key_byte(&self) -> u8;
    }

    struct Params {
        key_byte: u8,
    }

    impl TestParams for Params {
        fn key_byte(&self) -> u8 {
            self.key_byte
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestError {
        NotInitialised,
        OutputTooShort,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{self:?}")
        }
    }

    impl core::error::Error for TestError {}

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestInitError;

    impl fmt::Display for TestInitError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("key byte must not be zero")
        }
    }

    impl core::error::Error for TestInitError {}

    #[derive(Default)]
    struct TestMac {
        key_byte: Option<u8>,
        sum: u8,
    }

    impl Mac for TestMac {
        type Error = TestError;

        fn mac_size(&self) -> usize {
            1
        }

        fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
            if self.key_byte.is_none() {
                return Err(TestError::NotInitialised);
            }
            for &byte in input {
                self.sum = self.sum.wrapping_add(byte);
            }
            Ok(())
        }

        fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            let key_byte = self.key_byte.ok_or(TestError::NotInitialised)?;
            let tag = output.first_mut().ok_or(TestError::OutputTooShort)?;
            *tag = key_byte ^ self.sum;
            self.reset();
            Ok(1)
        }

        fn reset(&mut self) {
            self.sum = 0;
        }
    }

    impl<P: TestParams + ?Sized> MacInit<P> for TestMac {
        type Error = TestInitError;

        fn init(&mut self, params: &P) -> Result<(), Self::Error> {
            let key_byte = params.key_byte();
            if key_byte == 0 {
                return Err(TestInitError);
            }
            self.key_byte = Some(key_byte);
            self.reset();
            Ok(())
        }
    }

    #[test]
    fn initialized_mac_supports_dynamic_dispatch() {
        let params = Params { key_byte: 0xa5 };
        let mut concrete = TestMac::default();
        concrete.init(&params).unwrap();
        let mac: &mut dyn Mac<Error = TestError> = &mut concrete;

        assert_eq!(mac.mac_size(), 1);
        mac.update(&[1, 2, 3]).unwrap();

        let mut output = [0_u8; 1];
        assert_eq!(mac.do_final(&mut output), Ok(1));
        assert_eq!(output, [0xa3]);

        mac.update(&[4]).unwrap();
        assert_eq!(mac.do_final(&mut output), Ok(1));
        assert_eq!(output, [0xa1]);
    }

    #[test]
    fn initialization_accepts_concrete_and_trait_object_params() {
        let mut mac = TestMac::default();
        assert_eq!(mac.update(&[]), Err(TestError::NotInitialised));

        let params = Params { key_byte: 0x5a };
        mac.init(&params).unwrap();
        assert_eq!(mac.key_byte, Some(0x5a));

        let params: &dyn TestParams = &Params { key_byte: 0xa5 };
        mac.init(params).unwrap();
        assert_eq!(mac.key_byte, Some(0xa5));

        assert_eq!(mac.init(&Params { key_byte: 0 }), Err(TestInitError));
    }
}
