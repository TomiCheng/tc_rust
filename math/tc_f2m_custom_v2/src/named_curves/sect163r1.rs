use super::SecTNamedCurve;
use super::hex::hex;
use crate::SecT163FieldElement;
use core::marker::PhantomData;

/// SEC 2 sect163r1.
pub const SECT163R1: SecTNamedCurve<SecT163FieldElement, 21> = SecTNamedCurve {
    a: hex("07b6882caaefa84f9554ff8428bd88e246d2782ae2"),
    b: hex("0713612dcddcb40aab946bda29ca91f73af958afd9"),
    order: hex("03ffffffffffffffffffff48aab689c29ca710279b"),
    cofactor: 2,
    gx: hex("0369979697ab43897789566789567f787a7876a654"),
    gy: hex("00435edb42efafb2989d51fefce3c80988f41ff883"),
    field: PhantomData,
};
