//! Initialization errors specific to GCM-SIV key derivation.

use core::fmt;

/// A failure while initializing a GCM-SIV instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GcmSivInitError<I, E> {
    /// The underlying cipher does not use 16-byte blocks.
    InvalidBlockSize(usize),
    /// The master key is neither 16 nor 32 bytes.
    InvalidKeyLength(usize),
    /// The nonce is not exactly 12 bytes.
    InvalidNonceLength(usize),
    /// The requested authentication tag is not exactly 16 bytes.
    InvalidMacSize(usize),
    /// The initial associated data exceeds the RFC 8452 limit.
    InitialAadTooLong(usize),
    /// Initializing the underlying cipher with the master key failed.
    MasterKey(I),
    /// Encrypting a key-derivation block failed.
    KeyDerivation(E),
    /// Initializing the underlying cipher with the derived key failed.
    DerivedKey(I),
}

impl<I: fmt::Display, E: fmt::Display> fmt::Display for GcmSivInitError<I, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlockSize(bytes) => {
                write!(f, "invalid GCM-SIV block cipher size: {bytes} bytes")
            }
            Self::InvalidKeyLength(bytes) => {
                write!(f, "invalid GCM-SIV key length: {bytes} bytes")
            }
            Self::InvalidNonceLength(bytes) => {
                write!(f, "invalid GCM-SIV nonce length: {bytes} bytes")
            }
            Self::InvalidMacSize(bytes) => {
                write!(f, "invalid GCM-SIV authentication-tag size: {bytes} bytes")
            }
            Self::InitialAadTooLong(bytes) => {
                write!(f, "GCM-SIV initial AAD is too long: {bytes} bytes")
            }
            Self::MasterKey(error) => {
                write!(f, "GCM-SIV master-key initialization failed: {error}")
            }
            Self::KeyDerivation(error) => {
                write!(f, "GCM-SIV key derivation failed: {error}")
            }
            Self::DerivedKey(error) => {
                write!(f, "GCM-SIV derived-key initialization failed: {error}")
            }
        }
    }
}

impl<I: core::error::Error, E: core::error::Error> core::error::Error for GcmSivInitError<I, E> {}
