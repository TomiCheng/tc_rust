use tc_twofish_v2::TwofishEngine;

use super::specs::AlgorithmSpec;
use crate::cipher::engine::AnyEngine;

pub(super) const TWOFISH: AlgorithmSpec = AlgorithmSpec {
    names: &["TWOFISH"],
    block_size: 16,
    engine: || AnyEngine::new(TwofishEngine::new()),
    oids: &[],
};
