//! Extensions made from keys and certificates for a generator to add: BC's
//! `SubjectKeyIdentifierStructure` and `AuthorityKeyIdentifierStructure`.

mod key_identifier;

pub use key_identifier::{authority_key_identifier, key_identifier_of, subject_key_identifier};
