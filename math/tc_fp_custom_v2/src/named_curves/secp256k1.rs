use super::SecPNamedCurve;
use super::hex::hex;
use super::secp_named_curve::NamedGlv;
use crate::SecP256K1FieldElement;
use core::marker::PhantomData;

/// SEC 2 secp256k1.
pub const SECP256K1: SecPNamedCurve<SecP256K1FieldElement, 32> = SecPNamedCurve {
    a: hex("0000000000000000000000000000000000000000000000000000000000000000"),
    b: hex("0000000000000000000000000000000000000000000000000000000000000007"),
    order: hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
    cofactor: 1,
    gx: hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    gy: hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
    glv: Some(NamedGlv {
        beta: "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee",
        v1: [
            "3086d221a7d46bcde86c90e49284eb15",
            "-e4437ed6010e88286f547fa90abfe4c3",
        ],
        v2: [
            "114ca50f7a8e2f3f657c1108d9d44cfd8",
            "3086d221a7d46bcde86c90e49284eb15",
        ],
        g1: "3086d221a7d46bcde86c90e49284eb153dab",
        g2: "e4437ed6010e88286f547fa90abfe4c42212",
        bits: 272,
    }),
    field: PhantomData,
};
