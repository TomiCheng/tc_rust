use alloc::vec::Vec;

use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::multiplier::BaseMultiplier;

use crate::{FpCtCurve, FpCtPoint};

/// The Ct curve's own multiplication with its table kept: the 4-bit fixed window of
/// [`FpCtPoint::multiply`] on 0P to 15P, built once for the base. Constant time in the base
/// and the scalar.
pub struct FpCtPrecomputed<'a> {
    table: Vec<FpCtPoint<'a>>,
}

/// `new` builds the table, constant time.
impl<'a> BaseMultiplier<&'a FpCtCurve<'a>> for FpCtPrecomputed<'a> {
    fn new(base: FpCtPoint<'a>) -> Self {
        Self {
            table: base.window_table(),
        }
    }

    fn multiply(&self, scalar: &PaddedBigUint) -> FpCtPoint<'a> {
        FpCtPoint::multiply_window(&self.table, scalar)
    }
}
