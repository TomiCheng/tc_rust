//! ChaCha 系列的 stream cipher。沒有驗證：同一組金鑰與 nonce 不可重複使用，要保護訊息請改用 AEAD。

use tc_buffered_cipher::BufferedStreamCipher;
use tc_chacha::{ChaCha7539Engine, ChaChaEngine, XChaCha20Engine};

use super::specs::{Lengths, StandaloneSpec};
use crate::cipher::{Algorithm, AnyCipher};

/// Bernstein 原版 ChaCha20：金鑰 16 或 32 bytes，沒給時產生 16 bytes（同 BC 的 128 bits）；nonce 8 bytes。
pub(super) const CHACHA: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::ChaCha,
    names: &["CHACHA"],
    key: Lengths::new(16, 32, 16, 16),
    cipher: || AnyCipher::new(BufferedStreamCipher::new(ChaChaEngine::new())),
    oids: &[],
};

/// RFC 8439 的 ChaCha20：金鑰 32 bytes；nonce 12 bytes。BC 也接受 `CHACHA20` 這個名稱。
pub(super) const CHACHA7539: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::ChaCha7539,
    names: &["CHACHA7539", "CHACHA20"],
    key: Lengths::exact(32),
    cipher: || AnyCipher::new(BufferedStreamCipher::new(ChaCha7539Engine::new())),
    oids: &[],
};

/// XChaCha20：金鑰 32 bytes；nonce 24 bytes，長到可以每則訊息隨機產生。
pub(super) const XCHACHA20: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::XChaCha20,
    names: &["XCHACHA20"],
    key: Lengths::exact(32),
    cipher: || AnyCipher::new(BufferedStreamCipher::new(XChaCha20Engine::new())),
    oids: &[],
};
