use alloc::vec::Vec;

use crate::limb::Word;

mod add;
mod from;

#[derive(Clone, Debug)]
pub struct BigUint {
    magnitude: Vec<Word>,
}
