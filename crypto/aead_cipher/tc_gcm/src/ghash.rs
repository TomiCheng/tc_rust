//! Portable GHASH arithmetic used internally by GCM.

use crate::BLOCK_BYTES;

#[derive(Clone, Copy)]
pub(crate) struct Multiplier {
    h: [u8; BLOCK_BYTES],
}

impl Multiplier {
    pub(crate) const fn new(h: [u8; BLOCK_BYTES]) -> Self {
        Self { h }
    }

    pub(crate) fn multiply_h(&self, value: &mut [u8; BLOCK_BYTES]) {
        *value = multiply(value, &self.h);
    }
}

/// Multiplies two field elements in the bit ordering defined by SP 800-38D.
fn multiply(left: &[u8; BLOCK_BYTES], right: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
    let mut product = [0u8; BLOCK_BYTES];
    let mut factor = *right;

    for bit_index in 0..128 {
        let bit = (left[bit_index / 8] >> (7 - bit_index % 8)) & 1;
        let bit_mask = 0u8.wrapping_sub(bit);
        for index in 0..BLOCK_BYTES {
            product[index] ^= factor[index] & bit_mask;
        }

        let reduce = factor[BLOCK_BYTES - 1] & 1;
        let mut carry = 0u8;
        for byte in &mut factor {
            let next_carry = (*byte & 1) << 7;
            *byte = (*byte >> 1) | carry;
            carry = next_carry;
        }
        factor[0] ^= 0xe1 & 0u8.wrapping_sub(reduce);
    }

    product
}

#[cfg(test)]
mod tests {
    use super::{Multiplier, multiply};

    #[test]
    fn matches_nist_gcm_multiplication_example() {
        let h = 0x66e94bd4ef8a2c3b884cfa59ca342b2eu128.to_be_bytes();
        let value = 0x0388dace60b6a392f328c2b971b2fe78u128.to_be_bytes();
        let expected = 0x5e2ec746917062882c85b0685353deb7u128.to_be_bytes();

        assert_eq!(multiply(&value, &h), expected);

        let mut in_place = value;
        Multiplier::new(h).multiply_h(&mut in_place);
        assert_eq!(in_place, expected);
    }
}
