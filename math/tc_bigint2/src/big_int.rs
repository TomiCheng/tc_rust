//! Arbitrary-precision signed integers.

use alloc::vec::Vec;

use crate::{Limb, Word};

mod add;
mod boxed;
mod from;

/// A little-endian two's-complement integer whose precision grows as needed.
///
/// Zero uses an empty limb vector. Non-zero values have no redundant high
/// sign-extension limbs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BigInt {
    limbs: Vec<Limb>,
}

impl BigInt {
    pub(crate) fn as_limbs(&self) -> &[Limb] {
        &self.limbs
    }

    pub(crate) fn from_limbs(mut limbs: Vec<Limb>) -> Self {
        while limbs.len() > 1 {
            let high = limbs[limbs.len() - 1].0;
            let next = limbs[limbs.len() - 2].0;
            let next_is_negative = next >> (Word::BITS - 1) != 0;

            if (high == 0 && !next_is_negative) || (high == Word::MAX && next_is_negative) {
                limbs.pop();
            } else {
                break;
            }
        }

        if limbs == [Limb(0)] {
            limbs.clear();
        }

        Self { limbs }
    }
}
