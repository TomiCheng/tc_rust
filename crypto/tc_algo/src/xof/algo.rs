#[cfg(any(feature = "keccak", feature = "ascon-hash", feature = "blake"))]
mod init_xof;
#[cfg(any(feature = "keccak", feature = "blake", feature = "ascon-hash"))]
mod row;

#[cfg(feature = "ascon-hash")]
mod ascon;
#[cfg(feature = "blake")]
mod blake;
#[cfg(feature = "keccak")]
mod keccak;

use super::XofEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn XofEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the XOFs whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "keccak")]
    keccak::shake128,
    #[cfg(feature = "keccak")]
    keccak::shake256,
    #[cfg(feature = "keccak")]
    keccak::cshake128,
    #[cfg(feature = "keccak")]
    keccak::cshake256,
    #[cfg(feature = "keccak")]
    keccak::tuplehash128,
    #[cfg(feature = "keccak")]
    keccak::tuplehash256,
    #[cfg(feature = "keccak")]
    keccak::parallelhash128,
    #[cfg(feature = "keccak")]
    keccak::parallelhash256,
    #[cfg(feature = "blake")]
    blake::blake2xs,
    #[cfg(feature = "blake")]
    blake::blake3,
    #[cfg(feature = "ascon-hash")]
    ascon::ascon_xof128,
    #[cfg(feature = "ascon-hash")]
    ascon::ascon_cxof128,
    #[cfg(feature = "ascon-hash")]
    ascon::ascon_xof,
    #[cfg(feature = "ascon-hash")]
    ascon::ascon_xofa,
];
