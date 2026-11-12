#[cfg(any(
    feature = "cshake128",
    feature = "cshake256",
    feature = "tuplehash128",
    feature = "tuplehash256",
    feature = "ascon-cxof128",
    feature = "blake2xs",
    feature = "blake3",
))]
mod init_xof;
#[cfg(any(
    feature = "shake128",
    feature = "shake256",
    feature = "cshake128",
    feature = "cshake256",
    feature = "tuplehash128",
    feature = "tuplehash256",
    feature = "blake2xs",
    feature = "blake3",
    feature = "ascon-xof128",
    feature = "ascon-cxof128",
    feature = "ascon-xof",
    feature = "ascon-xofa",
))]
mod row;

#[cfg(any(
    feature = "ascon-xof128",
    feature = "ascon-cxof128",
    feature = "ascon-xof",
    feature = "ascon-xofa",
))]
mod ascon;
#[cfg(any(feature = "blake2xs", feature = "blake3",))]
mod blake;
#[cfg(any(
    feature = "shake128",
    feature = "shake256",
    feature = "cshake128",
    feature = "cshake256",
    feature = "tuplehash128",
    feature = "tuplehash256",
))]
mod keccak;

use super::XofEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn XofEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the XOFs whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "shake128")]
    keccak::shake128,
    #[cfg(feature = "shake256")]
    keccak::shake256,
    #[cfg(feature = "cshake128")]
    keccak::cshake128,
    #[cfg(feature = "cshake256")]
    keccak::cshake256,
    #[cfg(feature = "tuplehash128")]
    keccak::tuplehash128,
    #[cfg(feature = "tuplehash256")]
    keccak::tuplehash256,
    #[cfg(feature = "blake2xs")]
    blake::blake2xs,
    #[cfg(feature = "blake3")]
    blake::blake3,
    #[cfg(feature = "ascon-xof128")]
    ascon::ascon_xof128,
    #[cfg(feature = "ascon-cxof128")]
    ascon::ascon_cxof128,
    #[cfg(feature = "ascon-xof")]
    ascon::ascon_xof,
    #[cfg(feature = "ascon-xofa")]
    ascon::ascon_xofa,
];
