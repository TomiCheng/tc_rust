//! The key-agreement interface, after Bouncy Castle's `IBasicAgreement` and
//! `IRawAgreement`.

#![no_std]

mod traits;

pub use traits::{Agreement, AgreementInit};
