//! Ascon 的 AEAD。BC 的工廠沒有這一族，名稱是自訂的，也沒有 OID；引擎都是常數時間。
//! 引擎會拒絕用同一組金鑰與 nonce 再加密一次，但只記得自己上一次用過的：每則訊息都要重新 build 參數。

use tc_ascon_aead::{AsconAead128Engine, AsconLegacyEngine, AsconLegacyVariant};
use tc_buffered_cipher::BufferedAeadCipher;

use super::specs::{Lengths, StandaloneSpec};
use crate::cipher::{Algorithm, AnyCipher};

/// NIST SP 800-232 的 Ascon-AEAD128：金鑰與 nonce 16 bytes，tag 4 到 16 bytes，沒給時 16 bytes。
pub(super) const ASCON_AEAD128: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::AsconAead128,
    names: &["ASCON-AEAD128"],
    key: Lengths::exact(16),
    cipher: || AnyCipher::new(BufferedAeadCipher::new(AsconAead128Engine::new())),
    oids: &[],
};

/// Ascon v1.2 的 Ascon-128，只為了解開標準化以前的資料：金鑰與 nonce 16 bytes，tag 固定 16 bytes。
pub(super) const ASCON128: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::Ascon128,
    names: &["ASCON-128"],
    key: Lengths::exact(16),
    cipher: || {
        AnyCipher::new(BufferedAeadCipher::new(AsconLegacyEngine::new(
            AsconLegacyVariant::Ascon128,
        )))
    },
    oids: &[],
};

/// Ascon v1.2 的 Ascon-128a：長度同 Ascon-128。
pub(super) const ASCON128A: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::Ascon128a,
    names: &["ASCON-128A"],
    key: Lengths::exact(16),
    cipher: || {
        AnyCipher::new(BufferedAeadCipher::new(AsconLegacyEngine::new(
            AsconLegacyVariant::Ascon128a,
        )))
    },
    oids: &[],
};

/// Ascon v1.2 的 Ascon-80pq：金鑰 20 bytes，nonce 16 bytes，tag 固定 16 bytes。
pub(super) const ASCON80PQ: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::Ascon80pq,
    names: &["ASCON-80PQ"],
    key: Lengths::exact(20),
    cipher: || {
        AnyCipher::new(BufferedAeadCipher::new(AsconLegacyEngine::new(
            AsconLegacyVariant::Ascon80pq,
        )))
    },
    oids: &[],
};
