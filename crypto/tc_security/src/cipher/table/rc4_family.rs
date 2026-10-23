//! RC4 與 VMPC 系列 stream cipher：都以秘密狀態查表，不是常數時間，只為與 BC 相容保留。

#[cfg(feature = "rc4")]
use tc_asn1::NamedOid;
use tc_buffered_cipher::BufferedStreamCipher;
#[cfg(feature = "rc4")]
use tc_rc4_family::Rc4Engine;
#[cfg(feature = "vmpc")]
use tc_rc4_family::{VmpcEngine, VmpcKsa3Engine};

use super::specs::{Lengths, StandaloneSpec};
use crate::cipher::{Algorithm, AnyCipher};

/// RC4：金鑰 1 到 256 bytes，沒給時產生 16 bytes（同 BC 的 128 bits）；沒有 IV。名稱與 OID 照 BC。
#[cfg(feature = "rc4")]
pub(super) const ARC4: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::Rc4,
    names: &["ARC4", "RC4", "ARCFOUR"],
    key: Lengths::new(1, 256, 1, 16),
    cipher: || AnyCipher::new(BufferedStreamCipher::new(Rc4Engine::new())),
    oids: &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x04],
        "1.2.840.113549.3.4",
        "rc4",
    )],
};

/// VMPC：金鑰與 IV 都是 16 到 64 bytes，沒給時產生 16 bytes 的金鑰。
#[cfg(feature = "vmpc")]
pub(super) const VMPC: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::Vmpc,
    names: &["VMPC"],
    key: Lengths::new(16, 64, 1, 16),
    cipher: || AnyCipher::new(BufferedStreamCipher::new(VmpcEngine::new())),
    oids: &[],
};

/// VMPC-KSA3：長度同 VMPC。
#[cfg(feature = "vmpc")]
pub(super) const VMPC_KSA3: StandaloneSpec = StandaloneSpec {
    algorithm: Algorithm::VmpcKsa3,
    names: &["VMPC-KSA3", "VMPC_KSA3"],
    key: Lengths::new(16, 64, 1, 16),
    cipher: || AnyCipher::new(BufferedStreamCipher::new(VmpcKsa3Engine::new())),
    oids: &[],
};
