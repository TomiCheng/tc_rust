//! X9.42 key-derivation context: the `OtherInfo` hashed with the shared
//! secret to derive a Diffie-Hellman KEK, and its `KeySpecificInfo`.

mod key_specific_info;
mod other_info;

pub use key_specific_info::KeySpecificInfo;
pub use other_info::OtherInfo;
