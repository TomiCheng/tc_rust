use tc_sm4::Sm4Engine;

use super::specs::AlgorithmSpec;
use crate::cipher::engine::AnyEngine;

pub(super) const SM4: AlgorithmSpec = AlgorithmSpec {
    names: &["SM4"],
    block_size: 16,
    engine: || AnyEngine::new(Sm4Engine::new()),
    oids: &[],
};
