//! SRP-6a 密碼驗證金鑰交換，移植自 Bouncy Castle 的 `Srp6Client`、`Srp6Server`、
//! `Srp6VerifierGenerator` 與 `Srp6Utilities`。[`standard_groups`] 是 BC 的
//! `Srp6StandardGroups`：RFC 5054 公布的群組。
//!
//! 註冊時由密碼產生驗證值 v，server 保存鹽與 v；登入時雙方交換公開值 A、B，各自算出共享
//! 秘密 S，再以證明 M1、M2 互相確認，最後得到同一把工作階段金鑰。密碼不經過網路。
//!
//! ```
//! use tc_sha::Sha256Digest;
//! use tc_srp6::standard_groups::rfc5054_2048;
//! use tc_srp6::{Srp6Client, Srp6Server, Srp6VerifierGenerator};
//!
//! let group = rfc5054_2048();
//! let (identity, password) = (b"alice", b"password123");
//!
//! // Register
//! let mut salt = [0u8; 16];
//! rand::fill(&mut salt);
//! let mut generator = Srp6VerifierGenerator::new(Sha256Digest::new());
//! generator.init(&group)?;
//! let v = generator.generate_verifier(&salt, identity, password)?;
//! // server saves identity, salt, v
//!
//! // Login
//! // client -> identity -> server
//! let mut server = Srp6Server::new(Sha256Digest::new(), rand::rng());
//! server.init(&group, &v)?;
//! let public_b = server.generate_server_credentials()?;
//! // server -> salt, public_b -> client
//!
//! let mut client = Srp6Client::new(Sha256Digest::new(), rand::rng());
//! client.init(&group)?;
//! let public_a = client.generate_client_credentials(&salt, identity, password)?;
//! client.calculate_secret(&public_b)?;
//! let m1 = client.calculate_client_evidence_message()?;
//! // client -> public_a, m1 -> server
//!
//! server.calculate_secret(&public_a)?;
//! assert!(server.verify_client_evidence_message(&m1)?);
//! let m2 = server.calculate_server_evidence_message()?;
//! // server -> m2 -> client
//!
//! assert!(client.verify_server_evidence_message(&m2)?);
//!
//! // Both sides now hold the same session key
//! assert_eq!(client.calculate_session_key()?, server.calculate_session_key()?);
//! # Ok::<(), tc_srp6::Srp6Error>(())
//! ```

#![no_std]

extern crate alloc;

mod client;
mod error;
mod group;
mod server;
pub mod standard_groups;
#[cfg(test)]
mod tests;
pub mod utilities;
mod verifier_generator;

pub use client::Srp6Client;
pub use error::Srp6Error;
pub use group::Srp6GroupParameters;
pub use server::Srp6Server;
pub use verifier_generator::Srp6VerifierGenerator;
