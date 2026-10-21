use super::SecPNamedCurve;
use super::hex::hex;
use crate::SecP192K1FieldElement;
use core::marker::PhantomData;

/// SEC 2 secp192k1.
pub const SECP192K1: SecPNamedCurve<SecP192K1FieldElement, 24> = SecPNamedCurve {
    a: hex("000000000000000000000000000000000000000000000000"),
    b: hex("000000000000000000000000000000000000000000000003"),
    order: hex("fffffffffffffffffffffffe26f2fc170f69466a74defd8d"),
    cofactor: 1,
    gx: hex("db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d"),
    gy: hex("9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d"),
    field: PhantomData,
};
