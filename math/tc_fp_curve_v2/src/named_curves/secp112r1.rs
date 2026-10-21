use super::FpNamedCurve;
use super::hex::hex;

/// SEC 2 secp112r1, broken: about 56 bits of security.
pub const SECP112R1: FpNamedCurve<14> = FpNamedCurve {
    p: hex("db7c2abf62e35e668076bead208b"),
    a: hex("db7c2abf62e35e668076bead2088"),
    b: hex("659ef8ba043916eede8911702b22"),
    order: hex("db7c2abf62e35e7628dfac6561c5"),
    cofactor: 1,
    gx: hex("09487239995a5ee76b55f9c2f098"),
    gy: hex("a89ce5af8724c0a23e0e0ff77500"),
    glv: None,
};
