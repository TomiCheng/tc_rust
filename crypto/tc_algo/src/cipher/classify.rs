use core::convert::Infallible;

use tc_aead_cipher::{AeadError, AeadInitError};
use tc_block_cipher::{BlockError, InitError};
use tc_block_modes::{BlockModeError, BlockModeInitError};
use tc_buffered_cipher::BufferedError;

use crate::{AlgoError, ErrorKind};

// Sorts the errors of the layers underneath into an ErrorKind; the error itself travels as the
// source. Bad padding and a failed tag both come out as InvalidCiphertext: telling them apart is
// what a padding oracle needs
pub(super) trait Classify {
    fn kind(&self) -> ErrorKind;
}

impl Classify for AlgoError {
    fn kind(&self) -> ErrorKind {
        AlgoError::kind(self)
    }
}

impl Classify for Infallible {
    fn kind(&self) -> ErrorKind {
        match *self {}
    }
}

impl Classify for BlockError {
    fn kind(&self) -> ErrorKind {
        match self {
            BlockError::NotInitialised => ErrorKind::NotInitialized,
            _ => ErrorKind::DataLength,
        }
    }
}

impl Classify for InitError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::InvalidParams
    }
}

impl<E: Classify> Classify for BlockModeError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            BlockModeError::NotInitialised => ErrorKind::NotInitialized,
            BlockModeError::Cipher(error) => error.kind(),
            _ => ErrorKind::DataLength,
        }
    }
}

impl<E: Classify> Classify for BlockModeInitError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            BlockModeInitError::Cipher(error) => error.kind(),
            _ => ErrorKind::InvalidParams,
        }
    }
}

impl Classify for tc_stream_cipher::StreamError {
    fn kind(&self) -> ErrorKind {
        match self {
            tc_stream_cipher::StreamError::NotInitialised => ErrorKind::NotInitialized,
            // Too short an output, or more than the keystream of one key and IV
            _ => ErrorKind::DataLength,
        }
    }
}

// A key or IV of a length the stream cipher does not take
impl Classify for tc_stream_cipher::InitError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::InvalidParams
    }
}

impl<E: Classify> Classify for BufferedError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            BufferedError::NotInitialized => ErrorKind::NotInitialized,
            BufferedError::CorruptPadding => ErrorKind::InvalidCiphertext,
            BufferedError::Cipher(error) => error.kind(),
            // The lengths that do not fit: a partial last block, too long an input or too short
            // an output
            _ => ErrorKind::DataLength,
        }
    }
}

impl<E: Classify> Classify for AeadError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            // A finished GCM encryption takes a new init, so that no nonce is used twice
            AeadError::NotInitialized | AeadError::AlreadyFinalized => ErrorKind::NotInitialized,
            // Too short to hold the tag is told apart no more than a wrong tag
            AeadError::AuthenticationFailed | AeadError::CiphertextTooShort { .. } => {
                ErrorKind::InvalidCiphertext
            }
            AeadError::Cipher(error) => error.kind(),
            _ => ErrorKind::DataLength,
        }
    }
}

impl<E: Classify> Classify for AeadInitError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            AeadInitError::Cipher(error) => error.kind(),
            _ => ErrorKind::InvalidParams,
        }
    }
}

#[cfg(any(feature = "rsa", feature = "elgamal"))]
impl<E: Classify> Classify for tc_asym_encoding::EncodingError<E> {
    fn kind(&self) -> ErrorKind {
        use tc_asym_encoding::EncodingError;
        match self {
            EncodingError::Cipher(error) => error.kind(),
            EncodingError::NotInitialized => ErrorKind::NotInitialized,
            // A block that is not a valid PKCS#1 or OAEP encoding
            EncodingError::InvalidBlock => ErrorKind::InvalidCiphertext,
            EncodingError::InvalidPlaintextLength => ErrorKind::InvalidParams,
            _ => ErrorKind::DataLength,
        }
    }
}

#[cfg(feature = "rsa-iso9796")]
impl Classify for tc_asym_iso9796::Iso9796Error {
    fn kind(&self) -> ErrorKind {
        use tc_asym_iso9796::Iso9796Error;
        match self {
            Iso9796Error::Cipher(error) => error.kind(),
            Iso9796Error::NotInitialized => ErrorKind::NotInitialized,
            Iso9796Error::InvalidBlock => ErrorKind::InvalidCiphertext,
            // A modulus of a size it does not take
            Iso9796Error::UnsupportedKeySize => ErrorKind::InvalidParams,
            _ => ErrorKind::DataLength,
        }
    }
}

#[cfg(feature = "elgamal")]
impl Classify for tc_elgamal::ElGamalError {
    fn kind(&self) -> ErrorKind {
        use tc_elgamal::ElGamalError;
        match self {
            ElGamalError::NotInitialized => ErrorKind::NotInitialized,
            // Parameters or a key that fail their checks, or a key for the other direction
            ElGamalError::InvalidParameters(_)
            | ElGamalError::InvalidKey
            | ElGamalError::WrongKeyForDirection => ErrorKind::InvalidParams,
            // A gamma or phi outside [2, p - 2]
            ElGamalError::WeakCiphertext => ErrorKind::InvalidCiphertext,
            _ => ErrorKind::DataLength,
        }
    }
}

#[cfg(feature = "sm2")]
impl Classify for tc_sm2::Sm2Error {
    fn kind(&self) -> ErrorKind {
        use tc_sm2::Sm2Error;
        match self {
            Sm2Error::NotInitialized => ErrorKind::NotInitialized,
            // An empty message, too short a ciphertext or too short an output
            Sm2Error::EmptyInput | Sm2Error::CiphertextTooShort | Sm2Error::OutputTooShort => {
                ErrorKind::DataLength
            }
            // C1 not on the curve, or C3 not the hash of what C2 decrypts to
            Sm2Error::InvalidPoint | Sm2Error::InvalidCiphertext => ErrorKind::InvalidCiphertext,
            // A key for the other direction, or one that fails its checks
            _ => ErrorKind::InvalidParams,
        }
    }
}

#[cfg(feature = "naccache-stern")]
impl Classify for tc_naccache_stern::NaccacheSternError {
    fn kind(&self) -> ErrorKind {
        use tc_naccache_stern::NaccacheSternError;
        match self {
            NaccacheSternError::NotInitialized => ErrorKind::NotInitialized,
            // A ciphertext whose residues are not in the tables of the small primes
            NaccacheSternError::LookupFailed => ErrorKind::InvalidCiphertext,
            NaccacheSternError::InputTooLarge
            | NaccacheSternError::InvalidCiphertextLength
            | NaccacheSternError::OutputTooShort => ErrorKind::DataLength,
            // A key that fails its checks, or a public key to decrypt with
            _ => ErrorKind::InvalidParams,
        }
    }
}

#[cfg(feature = "rsa")]
impl Classify for tc_rsa::RsaError {
    fn kind(&self) -> ErrorKind {
        use tc_rsa::RsaError;
        match self {
            RsaError::NotInitialized => ErrorKind::NotInitialized,
            // An input of 0 or 1, or not below n - 1, or too short an output
            RsaError::InputTooSmall | RsaError::InputTooLarge | RsaError::OutputTooShort => {
                ErrorKind::DataLength
            }
            // A key that fails its checks, or whose CRT values do not agree
            _ => ErrorKind::InvalidParams,
        }
    }
}

// The AlgoError of an error from underneath: its kind, with the error itself as the source
pub(super) fn to_algo_error<E>(error: E) -> AlgoError
where
    E: Classify + core::error::Error + Send + Sync + 'static,
{
    AlgoError::with_source(error.kind(), error)
}
