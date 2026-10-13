//! RC6：只為了和既有格式相容，新設計應改用有驗證的 cipher。BC 產生金鑰時直接取亂數，沒有 weak key 要避開。

use tc_rc_cipher::{RC6_MAX_KEY_BYTES, Rc6Engine};

use super::specs::{AlgorithmSpec, Lengths};
use crate::cipher::Algorithm;
use crate::cipher::any_engine::AnyEngine;

/// RC6-32/20：區塊 16 bytes；金鑰 1 到 255 bytes，沒給時產生 32 bytes（同 BC 的 256 bits）。
pub(super) const RC6: AlgorithmSpec = AlgorithmSpec {
    algorithm: Algorithm::Rc6,
    names: &["RC6"],
    block_size: 16,
    key: Lengths::new(1, RC6_MAX_KEY_BYTES, 1, 32),
    engine: || AnyEngine::new(Rc6Engine::new()),
    oids: &[],
};
