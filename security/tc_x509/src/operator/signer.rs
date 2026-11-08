//! Signing under an `AlgorithmIdentifier`.

mod algo;
mod default_signature_factory;
mod signature_factory;
mod signer_entry;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub(crate) use default_signature_factory::DefaultSignatureFactory;
pub use signature_factory::SignatureFactory;
pub use signer_entry::SignerEntry;
