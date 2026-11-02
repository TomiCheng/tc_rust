//! Key agreements by name or OID, after Bouncy Castle's `AgreementUtilities`. An agreement is
//! found by name, such as `DH`, initialized with an [`AnyAgreementParams`] that holds one party's
//! private key, then given an [`AgreementPeer`] that holds the other party's public key for their
//! [`SharedSecret`], which a KDF turns into a key.

mod agreement_peer;
mod any_agreement;
mod any_agreement_params;
mod dyn_agreement;
mod entry;
mod functions;
mod helper;
mod shared_secret;
mod table;

pub use agreement_peer::AgreementPeer;
pub use any_agreement::AnyAgreement;
pub use any_agreement_params::AnyAgreementParams;
pub use entry::AgreementEntry;
pub use functions::{algorithms, get_by_name, get_by_oid};
pub use helper::calculate;
pub use shared_secret::SharedSecret;
pub use tc_agreement::{Agreement, AgreementInit};
