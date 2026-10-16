use super::hex::hex;
use super::{F2mNamedCurve, Taps};

/// SEC 2 sect163k1.
pub const SECT163K1: F2mNamedCurve<21> = F2mNamedCurve {
    m: 163,
    taps: Taps::Pentanomial(3, 6, 7),
    a: hex("000000000000000000000000000000000000000001"),
    b: hex("000000000000000000000000000000000000000001"),
    order: hex("04000000000000000000020108a2e0cc0d99f8a5ef"),
    cofactor: 2,
    gx: hex("02fe13c0537bbc11acaa07d793de4e6d5e5c94eee8"),
    gy: hex("0289070fb05d38ff58321f2e800536d538ccdaa3d9"),
};
