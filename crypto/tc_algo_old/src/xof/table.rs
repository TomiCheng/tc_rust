#[allow(
    unused_imports,
    reason = "the table is empty when every XOF feature is off"
)]
use tc_asn1::NamedOid;

use super::XofEntry;
#[allow(
    unused_imports,
    reason = "the table is empty when every XOF feature is off"
)]
use super::entry::Takes;
#[cfg(any(
    feature = "cshake128",
    feature = "cshake256",
    feature = "tuplehash128",
    feature = "tuplehash256",
    feature = "parallelhash128",
    feature = "parallelhash256",
    feature = "ascon-cxof128",
    feature = "ascon-xof-legacy"
))]
use super::{AnyXofParams, entry::BoxedXof};
#[cfg(any(
    feature = "cshake128",
    feature = "cshake256",
    feature = "tuplehash128",
    feature = "tuplehash256",
    feature = "parallelhash128",
    feature = "parallelhash256",
    feature = "ascon-cxof128",
    feature = "ascon-xof-legacy"
))]
use crate::AlgoError;
#[cfg(any(
    feature = "parallelhash128",
    feature = "parallelhash256",
    feature = "ascon-cxof128"
))]
use crate::ErrorKind;
#[allow(
    unused_imports,
    reason = "the table is empty when every XOF feature is off"
)]
use crate::need::Need::{Forbidden, Optional, Required};

// An XOF that takes nothing
#[allow(dead_code, reason = "unused when no such XOF's feature is on")]
const NOTHING: Takes = Takes {
    customization: Forbidden,
    function_name: Forbidden,
    block_size: Forbidden,
};

// An XOF that takes a customization string and can do without one
#[allow(dead_code, reason = "unused when no such XOF's feature is on")]
const CUSTOMIZATION: Takes = Takes {
    customization: Optional,
    function_name: Forbidden,
    block_size: Forbidden,
};

#[cfg(any(feature = "cshake128", feature = "cshake256"))]
fn cshake(bits: usize, params: &AnyXofParams) -> Result<BoxedXof, AlgoError> {
    Ok(Box::new(tc_keccak::CShakeDigest::new(
        bits,
        params.function_name().unwrap_or_default(),
        params.customization().unwrap_or_default(),
    )))
}

#[cfg(any(feature = "tuplehash128", feature = "tuplehash256"))]
fn tuple_hash(bits: usize, params: &AnyXofParams) -> Result<BoxedXof, AlgoError> {
    Ok(Box::new(tc_keccak::TupleHash::new(
        bits,
        params.customization().unwrap_or_default(),
    )))
}

// ParallelHash panics on a block size of zero, where here it is a value that init refuses
#[cfg(any(feature = "parallelhash128", feature = "parallelhash256"))]
fn parallel_hash(bits: usize, params: &AnyXofParams) -> Result<BoxedXof, AlgoError> {
    let block_size = params
        .block_size()
        .filter(|size| *size > 0)
        .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
    Ok(Box::new(tc_keccak::ParallelHash::new(
        bits,
        params.customization().unwrap_or_default(),
        block_size,
    )))
}

// Ascon-CXOF128 panics on a customization string over 256 bytes, where here init refuses it
#[cfg(feature = "ascon-cxof128")]
fn ascon_cxof128(params: &AnyXofParams) -> Result<BoxedXof, AlgoError> {
    let customization = params.customization().unwrap_or_default();
    if customization.len() > 256 {
        return Err(AlgoError::new(ErrorKind::InvalidParams));
    }
    Ok(Box::new(tc_ascon_hash::AsconCXof128::with_customization(
        customization,
    )))
}

// The two XOFs from before NIST standardized Ascon, deprecated in their crate; they are here for
// old data
#[cfg(feature = "ascon-xof-legacy")]
#[allow(deprecated, reason = "this row exists for old data")]
fn ascon_xof(_: &AnyXofParams) -> Result<BoxedXof, AlgoError> {
    Ok(Box::new(tc_ascon_hash::AsconXof::new(
        tc_ascon_hash::AsconXofParameters::AsconXof,
    )))
}

#[cfg(feature = "ascon-xof-legacy")]
#[allow(deprecated, reason = "this row exists for old data")]
fn ascon_xofa(_: &AnyXofParams) -> Result<BoxedXof, AlgoError> {
    Ok(Box::new(tc_ascon_hash::AsconXof::new(
        tc_ascon_hash::AsconXofParameters::AsconXofA,
    )))
}

// One row per XOF. Bouncy Castle has no factory for these, so the names are its classes' own, in
// upper case as in the other tables, and the only OIDs are those it has for SHAKE
pub(super) const XOFS: &[XofEntry] = &[
    #[cfg(feature = "shake128")]
    XofEntry::new(
        &["SHAKE128", "SHAKE-128"],
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b],
            "2.16.840.1.101.3.4.2.11",
            "id-shake128",
        )],
        NOTHING,
        |_| Ok(Box::new(tc_keccak::ShakeDigest::new(128))),
    ),
    #[cfg(feature = "shake256")]
    XofEntry::new(
        &["SHAKE256", "SHAKE-256"],
        &[NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c],
            "2.16.840.1.101.3.4.2.12",
            "id-shake256",
        )],
        NOTHING,
        |_| Ok(Box::new(tc_keccak::ShakeDigest::new(256))),
    ),
    #[cfg(feature = "cshake128")]
    XofEntry::new(
        &["CSHAKE128"],
        &[],
        Takes {
            customization: Optional,
            function_name: Optional,
            block_size: Forbidden,
        },
        |params| cshake(128, params),
    ),
    #[cfg(feature = "cshake256")]
    XofEntry::new(
        &["CSHAKE256"],
        &[],
        Takes {
            customization: Optional,
            function_name: Optional,
            block_size: Forbidden,
        },
        |params| cshake(256, params),
    ),
    #[cfg(feature = "tuplehash128")]
    XofEntry::new(&["TUPLEHASH128"], &[], CUSTOMIZATION, |params| {
        tuple_hash(128, params)
    }),
    #[cfg(feature = "tuplehash256")]
    XofEntry::new(&["TUPLEHASH256"], &[], CUSTOMIZATION, |params| {
        tuple_hash(256, params)
    }),
    #[cfg(feature = "parallelhash128")]
    XofEntry::new(
        &["PARALLELHASH128"],
        &[],
        Takes {
            customization: Optional,
            function_name: Forbidden,
            block_size: Required,
        },
        |params| parallel_hash(128, params),
    ),
    #[cfg(feature = "parallelhash256")]
    XofEntry::new(
        &["PARALLELHASH256"],
        &[],
        Takes {
            customization: Optional,
            function_name: Forbidden,
            block_size: Required,
        },
        |params| parallel_hash(256, params),
    ),
    #[cfg(feature = "blake2xs")]
    XofEntry::new(&["BLAKE2XS"], &[], NOTHING, |_| {
        Ok(Box::new(tc_blake::Blake2xsDigest::new()))
    }),
    #[cfg(feature = "blake3")]
    XofEntry::new(&["BLAKE3"], &[], NOTHING, |_| {
        Ok(Box::new(tc_blake::Blake3Digest::new()))
    }),
    #[cfg(feature = "ascon-xof128")]
    XofEntry::new(&["ASCON-XOF128"], &[], NOTHING, |_| {
        Ok(Box::new(tc_ascon_hash::AsconXof128::new()))
    }),
    #[cfg(feature = "ascon-cxof128")]
    XofEntry::new(&["ASCON-CXOF128"], &[], CUSTOMIZATION, ascon_cxof128),
    #[cfg(feature = "ascon-xof-legacy")]
    XofEntry::new(&["ASCON-XOF"], &[], NOTHING, ascon_xof),
    #[cfg(feature = "ascon-xof-legacy")]
    XofEntry::new(&["ASCON-XOFA"], &[], NOTHING, ascon_xofa),
];
