//! ECDH key agreement; a rewrite of `tc_ecdh` on `tc_ec_core_v2`.

#![no_std]

mod ecdh_basic_agreement;

pub use ecdh_basic_agreement::EcdhBasicAgreement;
