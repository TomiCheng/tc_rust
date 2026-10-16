use super::hex::hex;
use super::{F2mNamedCurve, Taps};

/// SEC 2 sect571r1.
pub const SECT571R1: F2mNamedCurve<72> = F2mNamedCurve {
    m: 571,
    taps: Taps::Pentanomial(2, 5, 10),
    a: hex(
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
    ),
    b: hex(
        "02f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a",
    ),
    order: hex(
        "03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe661ce18ff55987308059b186823851ec7dd9ca1161de93d5174d66e8382e9bb2fe84e47",
    ),
    cofactor: 2,
    gx: hex(
        "0303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19",
    ),
    gy: hex(
        "037bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b",
    ),
};
