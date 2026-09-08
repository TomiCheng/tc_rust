// //! 固定寬度的原始 RSA 基元。
// //!
// //! 本 crate 只提供未填充的 RSA 運算，不包含 PKCS#1 v1.5、OAEP、盲簽章或金鑰產生。
// //! 私鑰 CRT 路徑同時使用固定排程指數運算與每次運算重新取樣的 RSA 盲化：前者避免
// //! 指數位元改變運算排程，後者降低遠端計時及 Montgomery 額外約簡的可觀測性，兩者
// //! 防護的問題不同，不能互相取代。
// //!
// //! 支援的模數上限為 4096 位元，與 Bouncy Castle 預設的 16384 位元上限不同。
// //! 金鑰目前只驗證正值、奇數模數與奇數指數；小質因數篩選及模數合成性檢查仍待
// //! `tc_bigint` 質數模組整合後補上。
//
#![no_std]
//
extern crate alloc;
//
// mod core;
// mod engine;
mod error;
mod params;
mod rsa_core;
pub mod traits;

//
// pub use engine::RsaBlindedEngine;
pub use error::RsaError;
pub use params::{RsaKey, RsaKeyRef, RsaPrivateCrtKeyRef};
pub use traits::{Rsa, RsaCrt, RsaKeyParams, RsaPrivateCrtKeyParams};
