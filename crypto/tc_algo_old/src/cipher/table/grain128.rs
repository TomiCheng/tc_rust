use tc_buffered_cipher::BufferedAeadCipher;
use tc_grain128_aead::Grain128AeadEngine;

use super::compose::boxed;
use super::specs::AeadSpec;

// A 16-byte key, a 12-byte nonce and an 8-byte tag
pub(super) const GRAIN_128AEAD: AeadSpec = AeadSpec {
    names: &["GRAIN-128AEAD"],
    create: || boxed(BufferedAeadCipher::new(Grain128AeadEngine::new())),
    oids: &[],
};
