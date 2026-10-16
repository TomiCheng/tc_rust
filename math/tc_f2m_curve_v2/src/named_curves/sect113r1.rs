use super::hex::hex;
use super::{F2mNamedCurve, Taps};

/// SEC 2 sect113r1.
pub const SECT113R1: F2mNamedCurve<15> = F2mNamedCurve {
    m: 113,
    taps: Taps::Trinomial(9),
    a: hex("003088250ca6e7c7fe649ce85820f7"),
    b: hex("00e8bee4d3e2260744188be0e9c723"),
    order: hex("0100000000000000d9ccec8a39e56f"),
    cofactor: 2,
    gx: hex("009d73616f35f4ab1407d73562c10f"),
    gy: hex("00a52830277958ee84d1315ed31886"),
};
