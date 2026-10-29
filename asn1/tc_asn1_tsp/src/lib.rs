//! Time-stamp protocol (RFC 3161) and evidence record syntax (RFC 4998)
//! structures, after Bouncy Castle's `Asn1.Tsp`: time-stamp requests,
//! responses, the signed `TSTInfo`, and archive time-stamps.
//!
//! These types encode structure; checking the token's signature and that it
//! matches the request is the caller's job.
//!
//! `genTime` is a tc_asn1 `Asn1GeneralizedTime`, which follows the RFC 5280
//! profile and rejects fractional seconds; RFC 3161 allows them, so tokens that
//! use them do not decode.

#![no_std]

extern crate alloc;

mod accuracy;
mod archive_time_stamp;
mod archive_time_stamp_chain;
mod archive_time_stamp_sequence;
mod crypto_infos;
mod encryption_info;
mod evidence_record;
mod message_imprint;
mod partial_hashtree;
mod time_stamp_req;
mod time_stamp_resp;
mod tst_info;

pub use accuracy::Accuracy;
pub use archive_time_stamp::ArchiveTimeStamp;
pub use archive_time_stamp_chain::ArchiveTimeStampChain;
pub use archive_time_stamp_sequence::ArchiveTimeStampSequence;
pub use crypto_infos::CryptoInfos;
pub use encryption_info::EncryptionInfo;
pub use evidence_record::EvidenceRecord;
pub use message_imprint::MessageImprint;
pub use partial_hashtree::PartialHashtree;
pub use time_stamp_req::TimeStampReq;
pub use time_stamp_resp::TimeStampResp;
pub use tst_info::TstInfo;
