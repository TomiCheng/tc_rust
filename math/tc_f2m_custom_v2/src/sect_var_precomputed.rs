use crate::sect_element::SecTElement;
use crate::{SecTVarCurve, SecTVarPoint};
use alloc::boxed::Box;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::multiplier::BaseMultiplier;
use tc_ec_core_v2::{Curve, Point, Scalar, tnaf, wnaf};

/// The Var curve's own multiplication with its table kept: the window τ-adic NAF on a Koblitz
/// curve and the wNAF elsewhere, its window set by the order's width. On a Koblitz curve the
/// result holds, as in BC, only for points of the subgroup of order n. Variable time; only
/// for public scalars.
pub struct SecTVarPrecomputed<'a, F> {
    table: Table<'a, F>,
}

enum Table<'a, F> {
    TNaf(Box<tnaf::WTauNafTable<SecTVarPoint<'a, F>>>),
    WNaf(wnaf::WNafTable<SecTVarPoint<'a, F>>),
}

/// `new` builds the table, variable time; the base is public.
impl<'a, F: SecTElement> BaseMultiplier<&'a SecTVarCurve<F>> for SecTVarPrecomputed<'a, F> {
    fn new(base: SecTVarPoint<'a, F>) -> Self {
        let curve = base.curve();
        let table = if tnaf::is_koblitz(&curve) && !base.is_infinity() {
            Table::TNaf(Box::new(tnaf::WTauNafTable::new(
                &base,
                F::M as u32,
                SecTVarPoint::tau,
            )))
        } else {
            let bits = curve
                .order()
                .expect("the specialized curves know their order")
                .bit_length();
            Table::WNaf(wnaf::WNafTable::new(
                &base,
                wnaf::get_window_size(bits),
                true,
            ))
        };
        Self { table }
    }

    fn multiply(&self, scalar: &PaddedBigUint) -> SecTVarPoint<'a, F> {
        match &self.table {
            Table::TNaf(table) => tnaf::wtnaf_mul(table, scalar, SecTVarPoint::tau),
            Table::WNaf(table) => wnaf::wnaf_mul::<&SecTVarCurve<F>>(table, scalar),
        }
    }
}
