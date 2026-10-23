//! HC-128 與 HC-256 stream cipher：以秘密狀態查表，不是常數時間，只為與 BC 相容保留。

use tc_buffered_cipher::BufferedStreamCipher;
use tc_hc::{Hc128Engine, Hc256Engine};

use super::specs::{Lengths, StandaloneSpec};
use crate::cipher::{Algorithm, AnyCipher};

/// HC-128：金鑰與 IV 都是 16 bytes。
pub(super) const HC128: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::Hc128,
    names: &["HC128"],
    key: Lengths::exact(16),
    cipher: || AnyCipher::new(BufferedStreamCipher::new(Hc128Engine::new())),
    oids: &[],
};

/// HC-256：金鑰 16 或 32 bytes，沒給時產生 32 bytes（同 BC 的 256 bits）；IV 至少 16 bytes。
pub(super) const HC256: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::Hc256,
    names: &["HC256"],
    key: Lengths::new(16, 32, 16, 32),
    cipher: || AnyCipher::new(BufferedStreamCipher::new(Hc256Engine::new())),
    oids: &[],
};
