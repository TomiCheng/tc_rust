use alloc::boxed::Box;
use crate::BinField;

pub struct PaddedBinPoly {
    limbs: Box<[u64]>,
    field: BinField,
}
