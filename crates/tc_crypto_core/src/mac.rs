//! Message-authentication-code contracts.

/// An initialized streaming message authentication code.
///
/// Initialization is provided separately by [`MacInit`], keeping this
/// operational trait available for `dyn` dispatch.
pub trait Mac {
    /// The failure type returned by MAC operations.
    type Error: core::error::Error;

    /// Returns the algorithm name.
    fn algorithm_name(&self) -> &str;

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

/// Strongly typed initialization for a [`Mac`].
///
/// [`Params`](MacInit::Params) is a generic associated type so implementations
/// can accept parameter objects that borrow key material. It may also be an
/// unsized trait object when an implementation supports more than one
/// parameter-storage strategy.
pub trait MacInit: Mac {
    /// The parameter type accepted by [`init`](MacInit::init).
    type Params<'a>: ?Sized;

    /// Initializes the MAC with the supplied parameters.
    fn init(&mut self, params: &Self::Params<'_>) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use core::fmt;

    use super::{Mac, MacInit};

    trait TestParams {
        fn key_byte(&self) -> u8;
    }

    struct BorrowedParams<'a> {
        key: &'a u8,
    }

    impl TestParams for BorrowedParams<'_> {
        fn key_byte(&self) -> u8 {
            *self.key
        }
    }

    struct OwnedParams {
        key: u8,
    }

    impl TestParams for OwnedParams {
        fn key_byte(&self) -> u8 {
            self.key
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum TestError {
        OutputTooShort,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::OutputTooShort => f.write_str("output buffer is too short"),
            }
        }
    }

    impl core::error::Error for TestError {}

    #[derive(Default)]
    struct TestMac {
        key_byte: u8,
        sum: u8,
    }

    impl Mac for TestMac {
        type Error = TestError;

        fn algorithm_name(&self) -> &str {
            "TestMAC"
        }

        fn mac_size(&self) -> usize {
            1
        }

        fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
            for &byte in input {
                self.sum = self.sum.wrapping_add(byte);
            }
            Ok(())
        }

        fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            let tag = output.first_mut().ok_or(TestError::OutputTooShort)?;
            *tag = self.key_byte ^ self.sum;
            self.reset();
            Ok(1)
        }

        fn reset(&mut self) {
            self.sum = 0;
        }
    }

    impl MacInit for TestMac {
        type Params<'a> = dyn TestParams + 'a;

        fn init(&mut self, params: &Self::Params<'_>) -> Result<(), Self::Error> {
            self.key_byte = params.key_byte();
            self.reset();
            Ok(())
        }
    }

    #[test]
    fn initialized_mac_supports_dynamic_dispatch() {
        let params = OwnedParams { key: 0xa5 };
        let mut concrete = TestMac::default();
        concrete.init(&params).unwrap();
        let mac: &mut dyn Mac<Error = TestError> = &mut concrete;

        assert_eq!(mac.algorithm_name(), "TestMAC");
        assert_eq!(mac.mac_size(), 1);

        mac.update(&[1, 2, 3]).unwrap();
        let mut output = [0_u8; 1];
        assert_eq!(mac.do_final(&mut output), Ok(1));
        assert_eq!(output, [0xa3]);

        mac.update(&[4]).unwrap();
        assert_eq!(mac.do_final(&mut output), Ok(1));
        assert_eq!(output, [0xa1]);

        assert_eq!(mac.do_final(&mut []), Err(TestError::OutputTooShort));
    }

    #[test]
    fn init_accepts_borrowed_and_owned_parameter_implementations() {
        let key = 0xa5;
        let borrowed = BorrowedParams { key: &key };
        let mut mac = TestMac::default();

        mac.init(&borrowed).unwrap();
        assert_eq!(mac.key_byte, 0xa5);

        let owned = OwnedParams { key: 0x5a };
        mac.init(&owned).unwrap();
        assert_eq!(mac.key_byte, 0x5a);
    }
}
