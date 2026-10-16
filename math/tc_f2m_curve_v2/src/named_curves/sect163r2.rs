use super::hex::hex;
use super::{F2mNamedCurve, Taps};

/// SEC 2 sect163r2.
pub const SECT163R2: F2mNamedCurve<21> = F2mNamedCurve {
    m: 163,
    taps: Taps::Pentanomial(3, 6, 7),
    a: hex("000000000000000000000000000000000000000001"),
    b: hex("020a601907b8c953ca1481eb10512f78744a3205fd"),
    order: hex("040000000000000000000292fe77e70c12a4234c33"),
    cofactor: 2,
    gx: hex("03f0eba16286a2d57ea0991168d4994637e8343e36"),
    gy: hex("00d51fbc6c71a0094fa2cdd545b11c5c0c797324f1"),
};
