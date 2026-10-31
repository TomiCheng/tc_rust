//! Key and key pair generators by name or OID, after Bouncy Castle's `GeneratorUtilities`. A key
//! generator makes a [`SecretKey`](crate::params::SecretKey); a key pair generator makes a
//! [`KeyPair`] of a public and a private key. The operation parameters, such as an IV, come from
//! the factory of the algorithm that uses them.

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
