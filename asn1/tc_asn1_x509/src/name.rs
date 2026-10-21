//! `GeneralName` and its alternatives.

mod edi_party_name;
mod general_name;
mod general_names;
mod other_name;

pub use edi_party_name::EdiPartyName;
pub use general_name::GeneralName;
pub use general_names::GeneralNames;
pub use other_name::{OtherName, OtherNameValue};
