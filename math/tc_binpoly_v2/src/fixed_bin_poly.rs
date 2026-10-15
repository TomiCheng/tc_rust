use crate::BinField;

pub struct FixedBinPoly<const N: usize> {
    limbs: [u64; N],
    field: BinField,
}
