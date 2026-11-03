#[cfg(feature = "cast5")]
use tc_asn1::NamedOid;

use super::specs::AlgorithmSpec;
#[cfg(feature = "cast5")]
use super::specs::{ModeKind, PaddingKind};
use crate::cipher::engine::AnyEngine;

#[cfg(feature = "cast5")]
pub(super) const CAST5: AlgorithmSpec = AlgorithmSpec {
    names: &["CAST5"],
    block_size: 8,
    engine: || AnyEngine::new(tc_cast::Cast5Engine::new()),
    oids: &[(
        ModeKind::Cbc,
        PaddingKind::Pkcs7,
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 0x07, 0x42, 0x0a],
            "1.2.840.113533.7.66.10",
            "cast5CBC",
        )],
    )],
};

#[cfg(feature = "cast6")]
pub(super) const CAST6: AlgorithmSpec = AlgorithmSpec {
    names: &["CAST6"],
    block_size: 16,
    engine: || AnyEngine::new(tc_cast::Cast6Engine::new()),
    oids: &[],
};
