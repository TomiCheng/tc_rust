#[cfg(feature = "blake")]
mod blake2xs;
#[cfg(feature = "blake")]
mod blake3;
#[cfg(feature = "keccak")]
mod cshake;
#[cfg(feature = "keccak")]
mod parallel_hash;
#[cfg(feature = "keccak")]
mod tuple_hash;

#[cfg(feature = "ascon-hash")]
mod ascon;

#[cfg(feature = "ascon-hash")]
pub use ascon::AsconCXofParams;
#[cfg(feature = "blake")]
pub use blake2xs::Blake2xsParams;
#[cfg(feature = "blake")]
pub use blake3::Blake3Params;
#[cfg(feature = "keccak")]
pub use cshake::CShakeParams;
#[cfg(feature = "keccak")]
pub use parallel_hash::ParallelHashParams;
#[cfg(feature = "keccak")]
pub use tuple_hash::TupleHashParams;
