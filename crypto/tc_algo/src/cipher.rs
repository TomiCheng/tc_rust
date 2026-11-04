//! Ciphers by name or OID, after Bouncy Castle's `CipherUtilities`: block, stream, AEAD, IES and
//! asymmetric. A cipher is found by its full name, such as `AES/CBC/PKCS7PADDING`, initialized
//! with an [`AnyParams`](crate::params::AnyParams) for one direction, fed, then finished.

mod any_cipher;
pub(crate) mod classify;
mod dyn_cipher;
mod engine;
mod entry;
mod functions;
mod helper;
mod init_params;
mod table;

pub use any_cipher::AnyCipher;
pub use entry::CipherEntry;
pub use functions::{algorithms, get_by_name, get_by_oid};
pub use helper::{decrypt, encrypt};
pub use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, CipherDirection};
