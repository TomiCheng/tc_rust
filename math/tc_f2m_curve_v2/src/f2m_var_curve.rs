use crate::{F2mField, F2mFieldElement};
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::CoordinateSystem;

pub struct F2mVarCurve {
    field: F2mField,
    a: F2mFieldElement,
    b: F2mFieldElement,
    order: Option<PaddedBigUint>,
    cofactor: Option<PaddedBigUint>,
    coordinate_system: CoordinateSystem,
}
