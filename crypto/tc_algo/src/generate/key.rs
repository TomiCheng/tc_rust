//! Key generators by name or OID, after Bouncy Castle's `GeneratorUtilities`: each makes a
//! [`SecretKey`](crate::params::SecretKey) for the algorithms that take one, such as AES.

mod functions;
mod helper;
mod key_generator;
mod key_generator_entry;
mod table;

pub use functions::{algorithms, get_by_name, get_by_oid};
pub use helper::generate;
pub use key_generator::KeyGenerator;
pub use key_generator_entry::KeyGeneratorEntry;
