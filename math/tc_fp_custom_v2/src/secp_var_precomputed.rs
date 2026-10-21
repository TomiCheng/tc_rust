use crate::secp_element::SecPElement;
use crate::{SecPVarCurve, SecPVarPoint};
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::multiplier::BaseMultiplier;
use tc_ec_core_v2::{Curve, Point, Scalar, glv, wnaf};

/// The Var curve's own multiplication with its table kept: BC's GLV split on the k1 curves,
/// and the wNAF otherwise, the window set by the order's width. Variable time; only for
/// public scalars.
pub struct SecPVarPrecomputed<'a, F> {
    table: Table<'a, F>,
}

enum Table<'a, F> {
    Glv(glv::GlvTable<SecPVarPoint<'a, F>>, &'a glv::ScalarSplit),
    WNaf(wnaf::WNafTable<SecPVarPoint<'a, F>>),
}

/// `new` builds the table, variable time; the base is public.
impl<'a, F: SecPElement> BaseMultiplier<&'a SecPVarCurve<F>> for SecPVarPrecomputed<'a, F> {
    fn new(base: SecPVarPoint<'a, F>) -> Self {
        let curve = base.curve();
        let bits = curve
            .order()
            .expect("the specialized curves know their order")
            .bit_length();
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

    fn multiply(&self, scalar: &PaddedBigUint) -> SecPVarPoint<'a, F> {
        match &self.table {
            Table::Glv(table, split) => glv::glv_mul::<&SecPVarCurve<F>>(table, scalar, split),
            Table::WNaf(table) => wnaf::wnaf_mul::<&SecPVarCurve<F>>(table, scalar),
        }
    }
}
