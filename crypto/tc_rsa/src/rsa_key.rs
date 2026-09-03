//! RSA key-parameter contracts.

use crate::BigInt;

/// Parameters accepted by an RSA implementation.
pub trait RsaKeyParams<I: BigInt> {
    /// Returns the RSA modulus.
    fn modulus(&self) -> &I;

    /// Returns the public or private RSA exponent.
    fn exponent(&self) -> &I;
}

/// RSA private-key parameters used by the Chinese Remainder Theorem path.
pub trait RsaPrivateCrtKeyParams<I: BigInt>: RsaKeyParams<I> {
    /// Returns the public exponent.
    fn public_exponent(&self) -> &I;

    /// Returns the first prime factor.
    fn p(&self) -> &I;

    /// Returns the second prime factor.
    fn q(&self) -> &I;

    /// Returns the private exponent reduced modulo `p - 1`.
    fn dp(&self) -> &I;

    /// Returns the private exponent reduced modulo `q - 1`.
    fn dq(&self) -> &I;

    /// Returns the CRT coefficient, the inverse of `q` modulo `p`.
    fn q_inv(&self) -> &I;
}

#[cfg(test)]
mod tests {
    use super::{RsaKeyParams, RsaPrivateCrtKeyParams};
    use crate::BigInt;

    struct TestBigInt(u32);

    impl BigInt for TestBigInt {}

    struct TestKey {
        modulus: TestBigInt,
        exponent: TestBigInt,
    }

    impl RsaKeyParams<TestBigInt> for TestKey {
        fn modulus(&self) -> &TestBigInt {
            &self.modulus
        }

        fn exponent(&self) -> &TestBigInt {
            &self.exponent
        }
    }

    struct TestCrtKey {
        values: [TestBigInt; 8],
    }

    impl RsaKeyParams<TestBigInt> for TestCrtKey {
        fn modulus(&self) -> &TestBigInt {
            &self.values[0]
        }

        fn exponent(&self) -> &TestBigInt {
            &self.values[1]
        }
    }

    impl RsaPrivateCrtKeyParams<TestBigInt> for TestCrtKey {
        fn public_exponent(&self) -> &TestBigInt {
            &self.values[2]
        }

        fn p(&self) -> &TestBigInt {
            &self.values[3]
        }

        fn q(&self) -> &TestBigInt {
            &self.values[4]
        }

        fn dp(&self) -> &TestBigInt {
            &self.values[5]
        }

        fn dq(&self) -> &TestBigInt {
            &self.values[6]
        }

        fn q_inv(&self) -> &TestBigInt {
            &self.values[7]
        }
    }

    #[test]
    fn supports_caller_defined_integer_and_parameter_types() {
        let params = TestKey {
            modulus: TestBigInt(3233),
            exponent: TestBigInt(17),
        };
        let params: &dyn RsaKeyParams<TestBigInt> = &params;

        assert_eq!(params.modulus().0, 3233);
        assert_eq!(params.exponent().0, 17);
    }

    #[test]
    fn exposes_crt_values_through_the_trait_object() {
        let params = TestCrtKey {
            values: [
                TestBigInt(3233),
                TestBigInt(2753),
                TestBigInt(17),
                TestBigInt(61),
                TestBigInt(53),
                TestBigInt(53),
                TestBigInt(49),
                TestBigInt(38),
            ],
        };
        let params: &dyn RsaPrivateCrtKeyParams<TestBigInt> = &params;

        assert_eq!(params.modulus().0, 3233);
        assert_eq!(params.exponent().0, 2753);
        assert_eq!(params.public_exponent().0, 17);
        assert_eq!(params.p().0, 61);
        assert_eq!(params.q().0, 53);
        assert_eq!(params.dp().0, 53);
        assert_eq!(params.dq().0, 49);
        assert_eq!(params.q_inv().0, 38);
    }
}
