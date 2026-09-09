//! Modular inverse support for [`BigUint`].

use crate::{BigInt, BigUint};

impl BigUint {
    /// Returns the modular multiplicative inverse, when it exists.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        let value = BigInt::from_unsigned_le_u64(&self.to_le_u64());
        let modulus = BigInt::from_unsigned_le_u64(&modulus.to_le_u64());
        value
            .mod_inverse(&modulus)
            .map(|inverse| Self::from_le_u64(&inverse.to_le_u64()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_matches_known_values() {
        let three = BigUint::from(3_u8);
        assert_eq!(
            three.mod_inverse(&BigUint::from(7_u8)),
            Some(BigUint::from(5_u8))
        );
        assert_eq!(
            three.mod_inverse(&BigUint::from(10_u8)),
            Some(BigUint::from(7_u8))
        );
    }

    #[test]
    #[should_panic(expected = "modulus must be non-zero")]
    fn inverse_rejects_zero_modulus() {
        let _ = BigUint::from(1_u8).mod_inverse(&BigUint::default());
    }
}
