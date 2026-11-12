use tc_buffered_cipher::BufferedStreamCipher;
use tc_chacha::{ChaCha7539Engine, ChaChaEngine, XChaCha20Engine};

use super::compose::boxed;
use super::specs::{Need, StreamSpec};

// Bernstein's original ChaCha20: a 16- or 32-byte key and an 8-byte IV
pub(super) const CHACHA: StreamSpec = StreamSpec {
    names: &["CHACHA"],
    iv: Need::Required,
    create: || boxed(BufferedStreamCipher::new(ChaChaEngine::new())),
    oids: &[],
};

// ChaCha20 of RFC 8439: a 32-byte key and a 12-byte IV. Bouncy Castle takes CHACHA20 for it too
pub(super) const CHACHA7539: StreamSpec = StreamSpec {
    names: &["CHACHA7539", "CHACHA20"],
    iv: Need::Required,
    create: || boxed(BufferedStreamCipher::new(ChaCha7539Engine::new())),
    oids: &[],
};

// A 32-byte key and a 24-byte IV, long enough to be drawn at random for each message
pub(super) const XCHACHA20: StreamSpec = StreamSpec {
    names: &["XCHACHA20"],
    iv: Need::Required,
    create: || boxed(BufferedStreamCipher::new(XChaCha20Engine::new())),
    oids: &[],
};
