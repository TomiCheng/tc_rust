//! Key and key pair generators by name or OID, after Bouncy Castle's `GeneratorUtilities`. A key
//! generator makes a [`SecretKey`](crate::params::SecretKey); a key pair generator makes a
//! [`KeyPair`] of a public and a private key. The operation parameters, such as an IV, come from
//! the factory of the algorithm that uses them.
//!
//! # A key pair: RSA
//!
//! ```no_run
//! # #[cfg(feature = "rsa")] {
//! use tc_algo::generate::{self, KeyGenParams};
//! use tc_algo::params::{AnyKeyParams, AnyParams};
//!
//! // Find the generator by name; without init it makes 2048-bit keys with exponent 65537
//! let mut generator = generate::get_key_pair_generator("RSA")?;
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
//! [`generate_key_pair`] does the same in one step with the defaults:
//! `generate::generate_key_pair("RSA")?`.

#![allow(
    unused_variables,
    dead_code,
    unreachable_code,
    reason = "the interface comes first; the bodies are still todo"
)]

mod functions;
mod helper;
mod key_gen_params;
mod key_generator;
mod key_generator_entry;
mod key_pair;
mod key_pair_generator;
mod key_pair_generator_entry;
#[cfg(feature = "rsa")]
mod rsa_key_gen_params;
mod table;

pub use functions::{
    get_key_generator, get_key_generator_by_oid, get_key_pair_generator,
    get_key_pair_generator_by_oid, key_generators, key_pair_generators,
};
pub use helper::{generate_key, generate_key_pair};
pub use key_gen_params::KeyGenParams;
pub use key_generator::KeyGenerator;
pub use key_generator_entry::KeyGeneratorEntry;
pub use key_pair::KeyPair;
pub use key_pair_generator::KeyPairGenerator;
pub use key_pair_generator_entry::KeyPairGeneratorEntry;
#[cfg(feature = "rsa")]
pub use rsa_key_gen_params::RsaKeyGenParams;
