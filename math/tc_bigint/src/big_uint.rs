use alloc::vec::Vec;

use crate::limb::Limb;

#[derive(Clone, Debug)]
pub struct BigUint {
    magnitude: Vec<Limb>,
}
