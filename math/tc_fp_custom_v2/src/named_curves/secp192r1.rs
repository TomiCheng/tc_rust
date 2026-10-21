use super::SecPNamedCurve;
use super::hex::hex;
use crate::SecP192R1FieldElement;
use core::marker::PhantomData;

/// SEC 2 secp192r1, NIST P-192.
pub const SECP192R1: SecPNamedCurve<SecP192R1FieldElement, 24> = SecPNamedCurve {
    a: hex("fffffffffffffffffffffffffffffffefffffffffffffffc"),
    b: hex("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1"),
    order: hex("ffffffffffffffffffffffff99def836146bc9b1b4d22831"),
    cofactor: 1,
    gx: hex("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"),
    gy: hex("07192b95ffc8da78631011ed6b24cdd573f977a11e794811"),
    field: PhantomData,
};
