//! Key and key pair generators by name or OID, after Bouncy Castle's `GeneratorUtilities`, in
//! two factories that work alike: [`key`] makes a [`SecretKey`](crate::params::SecretKey) and
//! [`key_pair`] a [`KeyPair`](key_pair::KeyPair) of a public and a private key. The operation
//! parameters, such as an IV, come from the factory of the algorithm that uses them.
//!
//! # A key pair: RSA
//!
//! ```no_run
//! # #[cfg(feature = "rsa")] {
//! use tc_algo::generate::{self, KeyGenParams};
//! use tc_algo::params::{AnyKeyParams, AnyParams};
//!
//! // Find the generator by name; without init it makes 2048-bit keys with exponent 65537
//! let mut generator = generate::key_pair::get_by_name("RSA")?;
//!
//! // init changes the parameters: rsa() starts at the defaults, and each with_ changes one
//! generator.init(KeyGenParams::rsa().with_bits(2048))?;
//!
//! // Generate the pair, then hand each key to the factory that uses it: the public key to
//! // encrypt or verify, the private key to decrypt or sign
//! let pair = generator.generate()?;
//! let public = AnyParams::new(AnyKeyParams::Public(pair.public));
//! let private = AnyParams::new(AnyKeyParams::Private(pair.private));
//! # }
//! # Ok::<(), tc_algo::AlgoError>(())
//! ```
//!
//! [`key_pair::generate`] does the same in one step with the defaults:
//! `generate::key_pair::generate("RSA")?`.

pub mod key;
mod key_gen_params;
pub mod key_pair;
#[cfg(feature = "rsa")]
mod rsa_key_gen_params;

pub use key_gen_params::KeyGenParams;
#[cfg(feature = "rsa")]
pub use rsa_key_gen_params::RsaKeyGenParams;
