//! Content ciphers of tc_algo by the `AlgorithmIdentifier` an `EnvelopedData` records, whose
//! parameters, such as the IV, change with each message: by name to encrypt, with fresh parameters,
//! and by the one read to decrypt.
//!
//! ```
//! use tc_algo::params::key::KeyOwned;
//! use tc_algo_asn1::cipher::CipherDirection;
//! use tc_algo_asn1::{AlgoAsn1Builder, DefaultAlgoAsn1Builder};
//!
//! let asn1 = DefaultAlgoAsn1Builder::default().build();
//! let key = KeyOwned::new(vec![7; 16]);
//!
//! // Encrypting: a random IV goes into the AlgorithmIdentifier to record
//! let mut cipher = asn1.cipher().get_by_name("AES-128-CBC")?;
//! cipher.init(CipherDirection::Encrypt, &key)?;
//! let algorithm = cipher.algorithm().clone();
//! let mut sealed = cipher.update(b"attack at dawn")?;
//! sealed.extend(cipher.finalize()?);
//!
//! // Decrypting: the IV comes from the recorded AlgorithmIdentifier
//! let mut cipher = asn1.cipher().get_by_id(&algorithm)?;
//! cipher.init(CipherDirection::Decrypt, &key)?;
//! let mut opened = cipher.update(&sealed)?;
//! opened.extend(cipher.finalize()?);
//! assert_eq!(opened, b"attack at dawn");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod algo;
mod asn1_cipher;
mod cipher_entry;
mod cipher_provider;
mod default_asn1_cipher;
mod default_cipher_provider;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub use asn1_cipher::Asn1Cipher;
pub use cipher_entry::CipherEntry;
pub use cipher_provider::CipherProvider;
pub(crate) use default_asn1_cipher::DefaultAsn1Cipher;
pub(crate) use default_cipher_provider::DefaultCipherProvider;
pub use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, CipherDirection};
