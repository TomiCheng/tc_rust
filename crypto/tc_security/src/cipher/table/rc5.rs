//! RC5-32 與 RC5-64：只為了和既有格式相容，新設計應改用有驗證的 cipher。BC 產生金鑰時直接取亂數，沒有 weak key 要避開。

use tc_rc_cipher::{RC5_MAX_KEY_BYTES, Rc532Engine, Rc564Engine};

use super::specs::{AlgorithmSpec, Lengths};
use crate::cipher::Algorithm;
use crate::cipher::any_engine::AnyEngine;

/// RC5-32：區塊 8 bytes；金鑰 1 到 255 bytes，沒給時產生 16 bytes（同 BC 的 128 bits）。
pub(super) const RC5: AlgorithmSpec = AlgorithmSpec {
    algorithm: Algorithm::Rc5,
    names: &["RC5", "RC5-32"],
    block_size: 8,
    key: Lengths::new(1, RC5_MAX_KEY_BYTES, 1, 16),
    engine: || AnyEngine::new(Rc532Engine::new()),
    oids: &[],
};

/// 區塊 16 bytes；金鑰 1 到 255 bytes，沒給時產生 32 bytes（同 BC 的 256 bits）。
pub(super) const RC5_64: AlgorithmSpec = AlgorithmSpec {
    algorithm: Algorithm::Rc5_64,
    names: &["RC5-64"],
    block_size: 16,
    key: Lengths::new(1, RC5_MAX_KEY_BYTES, 1, 32),
    engine: || AnyEngine::new(Rc564Engine::new()),
    oids: &[],
};
