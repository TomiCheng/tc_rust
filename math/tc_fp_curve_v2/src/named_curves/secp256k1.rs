use super::NamedCurve;
use super::hex::hex;

/// SEC 2 secp256k1.
pub const SECP256K1: NamedCurve<32> = NamedCurve {
    p: hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
    a: hex("0000000000000000000000000000000000000000000000000000000000000000"),
    b: hex("0000000000000000000000000000000000000000000000000000000000000007"),
    order: hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
    cofactor: 1,
    gx: hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    gy: hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
};
