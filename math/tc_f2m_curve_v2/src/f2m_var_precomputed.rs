use alloc::boxed::Box;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::multiplier::BaseMultiplier;
use tc_ec_core_v2::{Point, Scalar, tnaf, wnaf};

use crate::{F2mVarCurve, F2mVarPoint};

/// The Var curve's own multiplication with its table kept: the window τ-adic NAF on a Koblitz
/// curve and the wNAF elsewhere, its window set by the order's width. On a Koblitz curve the
/// result holds, as in BC, only for points of the subgroup of order n. Variable time; only
/// for public scalars.
pub struct F2mVarPrecomputed<'a> {
    table: Table<'a>,
}

enum Table<'a> {
    TNaf(Box<tnaf::WTauNafTable<F2mVarPoint<'a>>>),
    WNaf(wnaf::WNafTable<F2mVarPoint<'a>>),
}

/// `new` builds the table, variable time; the base is public.
impl<'a> BaseMultiplier<&'a F2mVarCurve> for F2mVarPrecomputed<'a> {
    fn new(base: F2mVarPoint<'a>) -> Self {
        let curve = base.curve();
        let table = if tnaf::is_koblitz(&curve) && !base.is_infinity() {
            Table::TNaf(Box::new(tnaf::WTauNafTable::new(
                &base,
                curve.field().m(),
                F2mVarPoint::tau,
            )))
        } else {
            let bits = curve
                .order()
                .map_or(curve.field().m() as usize + 1, Scalar::bit_length);
            Table::WNaf(wnaf::WNafTable::new(
                &base,
                wnaf::get_window_size(bits),
                true,
            ))
        };
        Self { table }
    }

    fn multiply(&self, scalar: &PaddedBigUint) -> F2mVarPoint<'a> {
        match &self.table {
            Table::TNaf(table) => tnaf::wtnaf_mul(table, scalar, F2mVarPoint::tau),
            Table::WNaf(table) => wnaf::wnaf_mul::<&F2mVarCurve>(table, scalar),
        }
    }
}
