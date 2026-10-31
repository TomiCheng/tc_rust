// HC-128 and HC-256 look up tables of secret state, so they are not constant time
use tc_buffered_cipher::BufferedStreamCipher;
use tc_hc::{Hc128Engine, Hc256Engine};

use super::compose::boxed;
use super::specs::{Need, StreamSpec};

// A 16-byte key and a 16-byte IV
pub(super) const HC128: StreamSpec = StreamSpec {
    names: &["HC128"],
    iv: Need::Required,
    create: || boxed(BufferedStreamCipher::new(Hc128Engine::new())),
    oids: &[],
};

// A 16- or 32-byte key and an IV of at least 16 bytes, of which it reads the first 32
pub(super) const HC256: StreamSpec = StreamSpec {
    names: &["HC256"],
    iv: Need::Required,
    create: || boxed(BufferedStreamCipher::new(Hc256Engine::new())),
    oids: &[],
};
