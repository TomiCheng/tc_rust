use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::multiplier::BaseMultiplier;
use tc_ec_core_v2::{Point, Scalar, glv, wnaf};

use crate::{FpVarCurve, FpVarPoint};

/// The Var curve's own multiplication with its table kept: BC's GLV split on a curve given
/// one by [`FpVarCurve::with_glv`], and the wNAF otherwise, the window set by the order's
/// width. Variable time; only for public scalars.
pub struct FpVarPrecomputed<'a> {
    table: Table<'a>,
}

enum Table<'a> {
    Glv(glv::GlvTable<FpVarPoint<'a>>, &'a glv::ScalarSplit),
    WNaf(wnaf::WNafTable<FpVarPoint<'a>>),
}

/// `new` builds the table, variable time; the base is public.
impl<'a> BaseMultiplier<&'a FpVarCurve<'a>> for FpVarPrecomputed<'a> {
    fn new(base: FpVarPoint<'a>) -> Self {
        let curve = base.curve();
        let bits = curve
            .order()
            .map_or(curve.field().q().bits() as usize + 1, Scalar::bit_length);
        let table = match curve.glv() {
            Some((beta, split)) => {
                let width = wnaf::get_window_size(bits.div_ceil(2)).min(8);
                Table::Glv(glv::GlvTable::new(&base, width, |p| p.scale_x(beta)), split)
            }
            None => Table::WNaf(wnaf::WNafTable::new(
                &base,
                wnaf::get_window_size(bits),
                true,
            )),
        };
        Self { table }
    }

    fn multiply(&self, scalar: &PaddedBigUint) -> FpVarPoint<'a> {
        match &self.table {
            Table::Glv(table, split) => glv::glv_mul::<&FpVarCurve<'a>>(table, scalar, split),
            Table::WNaf(table) => wnaf::wnaf_mul::<&FpVarCurve<'a>>(table, scalar),
        }
    }
}
