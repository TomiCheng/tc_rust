use crate::secp_element::SecPElement;
use crate::{SecPCtCurve, SecPCtPoint};
use alloc::vec::Vec;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::multiplier::BaseMultiplier;

/// The Ct curve's own multiplication with its table kept: the 4-bit fixed window of
/// [`SecPCtPoint::multiply`] on 0P to 15P, built once for the base. Constant time in the base
/// and the scalar.
pub struct SecPCtPrecomputed<'a, F> {
    table: Vec<SecPCtPoint<'a, F>>,
}

/// `new` builds the table, constant time.
impl<'a, F: SecPElement> BaseMultiplier<&'a SecPCtCurve<F>> for SecPCtPrecomputed<'a, F> {
    fn new(base: SecPCtPoint<'a, F>) -> Self {
        Self {
            table: base.window_table(),
        }
    }

    fn multiply(&self, scalar: &PaddedBigUint) -> SecPCtPoint<'a, F> {
        SecPCtPoint::multiply_window(&self.table, scalar)
    }
}
