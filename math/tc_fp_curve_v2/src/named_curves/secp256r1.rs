use super::FpNamedCurve;
use super::hex::hex;

/// SEC 2 secp256r1, NIST P-256.
pub const SECP256R1: FpNamedCurve<32> = FpNamedCurve {
    p: hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
    a: hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
    b: hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
    order: hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
    cofactor: 1,
    gx: hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
    gy: hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    glv: None,
};
