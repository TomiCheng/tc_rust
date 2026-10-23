//! Salsa20 stream cipher。沒有驗證：同一組金鑰與 IV 不可重複使用。

use tc_buffered_cipher::BufferedStreamCipher;
use tc_salsa20::Salsa20Engine;

use super::specs::{Lengths, StandaloneSpec};
use crate::cipher::{Algorithm, AnyCipher};

/// 金鑰 16 或 32 bytes，沒給時產生 16 bytes（同 BC 的 128 bits）；IV 8 bytes。
pub(super) const SALSA20: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::Salsa20,
    names: &["SALSA20"],
    key: Lengths::new(16, 32, 16, 16),
    cipher: || AnyCipher::new(BufferedStreamCipher::new(Salsa20Engine::new())),
    oids: &[],
};
