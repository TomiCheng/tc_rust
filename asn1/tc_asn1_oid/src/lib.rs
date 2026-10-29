//! Object identifier tables from the Bouncy Castle `Asn1` folders that hold
//! nothing else: standards bodies, national schemes and vendors. Named curve
//! parameters live with the curve factories; structures live in their own
//! crates.

#![no_std]

mod anssi_id;
mod bsi_id;
mod cryptlib_id;
mod eac_id;
mod edec_id;
mod gm_id;
mod gnu_id;
mod gsma_id;
mod iana_id;
mod isara_id;
mod kisa_id;
mod nist_id;
mod nsri_id;
mod ntt_id;
mod oiw_id;
mod sec_id;
mod teletrust_id;

pub use anssi_id::AnssiId;
pub use bsi_id::BsiId;
pub use cryptlib_id::CryptlibId;
pub use eac_id::EacId;
pub use edec_id::EdecId;
pub use gm_id::GmId;
pub use gnu_id::GnuId;
pub use gsma_id::GsmaId;
pub use iana_id::IanaId;
pub use isara_id::IsaraId;
pub use kisa_id::KisaId;
pub use nist_id::NistId;
pub use nsri_id::NsriId;
pub use ntt_id::NttId;
pub use oiw_id::OiwId;
pub use sec_id::SecId;
pub use teletrust_id::TeletrustId;
