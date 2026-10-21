use super::SecPNamedCurve;
use super::hex::hex;
use crate::SM2P256V1FieldElement;
use core::marker::PhantomData;

/// GM/T 0003 SM2 curve sm2p256v1.
pub const SM2P256V1: SecPNamedCurve<SM2P256V1FieldElement, 32> = SecPNamedCurve {
    a: hex("fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc"),
    b: hex("28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93"),
    order: hex("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123"),
    cofactor: 1,
    gx: hex("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"),
    gy: hex("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"),
    field: PhantomData,
};
