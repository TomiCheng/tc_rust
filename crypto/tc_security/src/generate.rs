//! Key and parameter generators found by name, after Bouncy Castle's `GeneratorUtilities` and
//! `ParameterUtilities.GenerateParameters`.
//!
//! Calling `init` is optional: a generator uses its defaults until it is called.
//!
//! # A symmetric key: AES
//!
//! ```
//! # #[cfg(feature = "aes")] {
//! use tc_security::{cipher, generate};
//!
//! // 1. Find the generator by name; the name sets the size: AES256 is 256 bits.
//! let mut generator = generate::get_by_name("AES256")?.generator();
//! let key = generator.generate_key()?;
//!
//! // 2. Encrypt and decrypt with the key.
//! let mut aes = cipher::get_by_name("AES/ECB/PKCS7Padding")?.cipher();
//! let sealed = cipher::encrypt(&mut aes, &key, b"attack at dawn")?;
//! let opened = cipher::decrypt(&mut aes, &key, &sealed)?;
//! # assert_eq!(opened, b"attack at dawn");
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # A key pair: RSA
//!
//! ```
//! # #[cfg(feature = "rsa")] {
//! use tc_security::generate::{self, KeyGenParams};
//!
//! // 1. Find the generator by name; without init it makes 2048-bit keys with exponent 65537.
//! let mut generator = generate::get_by_name("RSA")?.generator();
//!
//! // 2. Call init to change the parameters, such as the size.
//! generator.init(&KeyGenParams::Basic { strength: 2048 })?;
//!
//! // 3. Generate the pair, both AnyParams::Rsa: encrypt with the public key, decrypt with the private one.
//! let (public, private) = generator.generate_key_pair()?;
//! # assert!(matches!(public, tc_security::params::AnyParams::Rsa { .. }));
//! # assert!(matches!(private, tc_security::params::AnyParams::Rsa { .. }));
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod algorithms;
mod generator;
mod generator_entry;
mod key_gen_params;
mod table;

pub use algorithms::{algorithms, get_by_name, get_by_oid};
pub use generator::Generator;
pub use generator_entry::GeneratorEntry;
pub use key_gen_params::KeyGenParams;
