//! Key pair generators by name or OID, after Bouncy Castle's `GeneratorUtilities`: each makes a
//! [`KeyPair`] of a public and a private key, such as for RSA or DH.

mod functions;
mod helper;
mod key_pair_generator;
mod key_pair_generator_entry;
mod pair;
mod table;

pub use functions::{algorithms, get_by_name, get_by_oid};
pub use helper::generate;
pub use key_pair_generator::KeyPairGenerator;
pub use key_pair_generator_entry::KeyPairGeneratorEntry;
pub use pair::KeyPair;
