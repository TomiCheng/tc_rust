use super::hex::hex;
use super::{F2mNamedCurve, Taps};

/// SEC 2 sect233k1.
pub const SECT233K1: F2mNamedCurve<30> = F2mNamedCurve {
    m: 233,
    taps: Taps::Trinomial(74),
    a: hex("000000000000000000000000000000000000000000000000000000000000"),
    b: hex("000000000000000000000000000000000000000000000000000000000001"),
    order: hex("008000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf"),
    cofactor: 4,
    gx: hex("017232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126"),
    gy: hex("01db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3"),
};
