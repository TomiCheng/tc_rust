use super::FpNamedCurve;
use super::hex::hex;

/// SEC 2 secp128r2, weak. The cofactor is 4, so the complete formulas of [`FpCtCurve`]
/// hold only in the subgroup of `G`: a point outside it may give a wrong result.
pub const SECP128R2: FpNamedCurve<16> = FpNamedCurve {
    p: hex("fffffffdffffffffffffffffffffffff"),
    a: hex("d6031998d1b3bbfebf59cc9bbff9aee1"),
    b: hex("5eeefca380d02919dc2c6558bb6d8a5d"),
    order: hex("3fffffff7fffffffbe0024720613b5a3"),
    cofactor: 4,
    gx: hex("7b6aa5d85e572983e6fb32a7cdebc140"),
    gy: hex("27b6916a894d3aee7106fe805fc34b44"),
    glv: None,
};
