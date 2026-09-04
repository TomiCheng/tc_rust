use alloc::vec::Vec;

use crate::limb::Word;

#[derive(Clone, Debug)]
pub struct BigUint {
    magnitude: Vec<Word>,
}
