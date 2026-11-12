#[cfg(feature = "chacha20-poly1305")]
use tc_asn1::NamedOid;
use tc_buffered_cipher::BufferedAeadCipher;

use super::compose::boxed;
use super::specs::AeadSpec;

// RFC 8439: a 32-byte key, a 12-byte nonce and a 16-byte tag. The OID is that of RFC 8103, as
// Bouncy Castle maps it
#[cfg(feature = "chacha20-poly1305")]
pub(super) const CHACHA20_POLY1305: AeadSpec = AeadSpec {
    names: &["CHACHA20-POLY1305"],
    create: || {
        boxed(BufferedAeadCipher::new(
            tc_chacha_aead::ChaCha20Poly1305Engine::new(),
        ))
    },
    oids: &[NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x12,
        ],
        "1.2.840.113549.1.9.16.3.18",
        "id-alg-AEADChaCha20Poly1305",
    )],
};

// A 24-byte nonce, long enough to be drawn at random for each message
#[cfg(feature = "xchacha20-poly1305")]
pub(super) const XCHACHA20_POLY1305: AeadSpec = AeadSpec {
    names: &["XCHACHA20-POLY1305"],
    create: || {
        boxed(BufferedAeadCipher::new(
            tc_chacha_aead::XChaCha20Poly1305Engine::new(),
        ))
    },
    oids: &[],
};
