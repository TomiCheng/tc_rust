#![no_std]

//! X.509（RFC 5280）的具名結構：`AlgorithmIdentifier`、`SubjectPublicKeyInfo`、
//! `Name`、`Validity`…… 建在 `tc_asn1` 的通用型別之上。
//!
//! 分在另一個 crate 是因為變動速度不同：X.690 不會改，PKIX 的結構會一直加。

extern crate alloc;

mod algorithm_identifier;

pub use algorithm_identifier::{AlgorithmIdentifier, AlgorithmParameters};
