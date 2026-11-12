use tc_buffered_cipher::BufferedStreamCipher;
use tc_salsa20::Salsa20Engine;

use super::compose::boxed;
use super::specs::{Need, StreamSpec};

// A 16- or 32-byte key and an 8-byte IV
pub(super) const SALSA20: StreamSpec = StreamSpec {
    names: &["SALSA20"],
    iv: Need::Required,
    create: || boxed(BufferedStreamCipher::new(Salsa20Engine::new())),
    oids: &[],
};
