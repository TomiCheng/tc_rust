use tc_buffered_cipher::BufferedAeadCipher;

use super::compose::boxed;
use super::specs::AeadSpec;

// NIST SP 800-232: a 16-byte key, a 16-byte nonce and a tag of 4 to 16 bytes
#[cfg(feature = "ascon-aead128")]
pub(super) const ASCON_AEAD128: AeadSpec = AeadSpec {
    names: &["ASCON-AEAD128"],
    create: || {
        boxed(BufferedAeadCipher::new(
            tc_ascon_aead::AsconAead128Engine::new(),
        ))
    },
    oids: &[],
};

// Ascon v1.2, which SP 800-232 replaced: a 16-byte nonce and tag, and a 16-byte key but for
// Ascon-80pq, whose key is 20 bytes
#[cfg(feature = "ascon-legacy")]
pub(super) const ASCON_128: AeadSpec = AeadSpec {
    names: &["ASCON-128"],
    create: || legacy(tc_ascon_aead::AsconLegacyVariant::Ascon128),
    oids: &[],
};

#[cfg(feature = "ascon-legacy")]
pub(super) const ASCON_128A: AeadSpec = AeadSpec {
    names: &["ASCON-128A"],
    create: || legacy(tc_ascon_aead::AsconLegacyVariant::Ascon128a),
    oids: &[],
};

#[cfg(feature = "ascon-legacy")]
pub(super) const ASCON_80PQ: AeadSpec = AeadSpec {
    names: &["ASCON-80PQ"],
    create: || legacy(tc_ascon_aead::AsconLegacyVariant::Ascon80pq),
    oids: &[],
};

#[cfg(feature = "ascon-legacy")]
fn legacy(
    variant: tc_ascon_aead::AsconLegacyVariant,
) -> Box<dyn crate::cipher::dyn_cipher::DynCipher> {
    boxed(BufferedAeadCipher::new(
        tc_ascon_aead::AsconLegacyEngine::new(variant),
    ))
}
