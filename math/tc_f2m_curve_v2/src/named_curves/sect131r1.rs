use super::hex::hex;
use super::{F2mNamedCurve, Taps};

/// SEC 2 sect131r1.
pub const SECT131R1: F2mNamedCurve<17> = F2mNamedCurve {
    m: 131,
    taps: Taps::Pentanomial(2, 3, 8),
    a: hex("07a11b09a76b562144418ff3ff8c2570b8"),
    b: hex("0217c05610884b63b9c6c7291678f9d341"),
    order: hex("0400000000000000023123953a9464b54d"),
    cofactor: 2,
    gx: hex("0081baf91fdf9833c40f9c181343638399"),
    gy: hex("078c6e7ea38c001f73c8134b1b4ef9e150"),
};
