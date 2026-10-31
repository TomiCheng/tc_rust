//! J-PAKE 密碼認證金鑰交換，移植自 Bouncy Castle 的 `JPakeParticipant`。雙方只共有一個
//! 密碼，交換兩輪酬載後算出同一份協商結果；可選的第三輪互相確認對方用了同一個密碼。
//! [`standard_groups`] 是 BC 的 `JPakePrimeOrderGroups`。
//!
//! ```
//! use tc_jpake::{JPakeParams, JPakeParticipant};
//!
//! // 雙方共有同一個密碼，各用不同的參與者 ID；群組預設是 NIST 的 3072 位元群組。
//! let mut alice = JPakeParticipant::new(rand::rng());
//! alice.init(&JPakeParams::new("alice", b"password"))?;
//! let mut bob = JPakeParticipant::new(rand::rng());
//! bob.init(&JPakeParams::new("bob", b"password"))?;
//!
//! // 第一輪：互寄 g^x1、g^x2 與零知識證明，各自驗證對方的。
//! let alice_round1 = alice.create_round1_payload_to_send()?;
//! let bob_round1 = bob.create_round1_payload_to_send()?;
//! alice.validate_round1_payload_received(&bob_round1)?;
//! bob.validate_round1_payload_received(&alice_round1)?;
//!
//! // 第二輪：互寄混入密碼的 A 與它的證明。
//! let alice_round2 = alice.create_round2_payload_to_send()?;
//! let bob_round2 = bob.create_round2_payload_to_send()?;
//! alice.validate_round2_payload_received(&bob_round2)?;
//! bob.validate_round2_payload_received(&alice_round2)?;
//!
//! // 各自算出協商結果，之後要再經過 KDF 才能當作金鑰。
//! let alice_key = alice.calculate_keying_material()?;
//! let bob_key = bob.calculate_keying_material()?;
//!
//! // 第三輪：互寄 MacTag，確認對方用的是同一個密碼。
//! let alice_round3 = alice.create_round3_payload_to_send(&alice_key)?;
//! let bob_round3 = bob.create_round3_payload_to_send(&bob_key)?;
//! alice.validate_round3_payload_received(&bob_round3, &alice_key)?;
//! bob.validate_round3_payload_received(&alice_round3, &bob_key)?;
//!
//! assert_eq!(*alice_key, *bob_key);
//! # Ok::<(), tc_jpake::JPakeError>(())
//! ```

#![no_std]

extern crate alloc;

mod error;
mod group;
mod params;
mod participant;
mod payloads;
pub mod standard_groups;
mod utilities;

pub use error::JPakeError;
pub use group::JPakePrimeOrderGroup;
pub use params::JPakeParams;
pub use participant::{JPakeParticipant, JPakeState};
pub use payloads::{
    JPakeRound1Payload, JPakeRound2Payload, JPakeRound3Payload, JPakeZeroKnowledgeProof,
};
