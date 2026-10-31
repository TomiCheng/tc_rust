use tc_threefish::{Threefish256Engine, Threefish512Engine, Threefish1024Engine};

use super::specs::AlgorithmSpec;
use crate::cipher::engine::AnyEngine;

// The key is as long as the block, and a bare key gives a zero tweak, as in Bouncy Castle. The
// blocks are too large for the AEAD modes
pub(super) const THREEFISH_256: AlgorithmSpec = AlgorithmSpec {
    names: &["THREEFISH-256"],
    block_size: 32,
    engine: || AnyEngine::new(Threefish256Engine::new()),
    oids: &[],
};

pub(super) const THREEFISH_512: AlgorithmSpec = AlgorithmSpec {
    names: &["THREEFISH-512"],
    block_size: 64,
    engine: || AnyEngine::new(Threefish512Engine::new()),
    oids: &[],
};

pub(super) const THREEFISH_1024: AlgorithmSpec = AlgorithmSpec {
    names: &["THREEFISH-1024"],
    block_size: 128,
    engine: || AnyEngine::new(Threefish1024Engine::new()),
    oids: &[],
};
