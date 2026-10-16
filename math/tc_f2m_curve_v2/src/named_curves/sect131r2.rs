use super::hex::hex;
use super::{F2mNamedCurve, Taps};

/// SEC 2 sect131r2.
pub const SECT131R2: F2mNamedCurve<17> = F2mNamedCurve {
    m: 131,
    taps: Taps::Pentanomial(2, 3, 8),
    a: hex("03e5a88919d7cafcbf415f07c2176573b2"),
    b: hex("04b8266a46c55657ac734ce38f018f2192"),
    order: hex("0400000000000000016954a233049ba98f"),
    cofactor: 2,
    gx: hex("0356dcd8f2f95031ad652d23951bb366a8"),
    gy: hex("0648f06d867940a5366d9e265de9eb240f"),
};
