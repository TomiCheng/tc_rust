use super::hex::hex;
use super::{F2mNamedCurve, Taps};

/// SEC 2 sect233r1.
pub const SECT233R1: F2mNamedCurve<30> = F2mNamedCurve {
    m: 233,
    taps: Taps::Trinomial(74),
    a: hex("000000000000000000000000000000000000000000000000000000000001"),
    b: hex("0066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad"),
    order: hex("01000000000000000000000000000013e974e72f8a6922031d2603cfe0d7"),
    cofactor: 2,
    gx: hex("00fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b"),
    gy: hex("01006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052"),
};
