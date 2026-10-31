use super::specs::AlgorithmSpec;
use crate::cipher::engine::AnyEngine;

#[cfg(feature = "serpent")]
pub(super) const SERPENT: AlgorithmSpec = AlgorithmSpec {
    names: &["SERPENT"],
    block_size: 16,
    engine: || AnyEngine::new(tc_serpent_v2::SerpentEngine::new()),
    oids: &[],
};

// Serpent with the byte order of an old Bouncy Castle, kept for the data it made
#[cfg(feature = "tnepres")]
pub(super) const TNEPRES: AlgorithmSpec = AlgorithmSpec {
    names: &["TNEPRES"],
    block_size: 16,
    engine: || AnyEngine::new(tc_serpent_v2::TnepresEngine::new()),
    oids: &[],
};
