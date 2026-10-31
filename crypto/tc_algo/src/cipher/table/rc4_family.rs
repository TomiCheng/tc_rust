// RC4 and VMPC look up tables of secret state, so they are not constant time
#[cfg(feature = "rc4")]
use tc_asn1::NamedOid;
use tc_buffered_cipher::BufferedStreamCipher;
#[cfg(feature = "rc4")]
use tc_rc4_family::Rc4Engine;
#[cfg(feature = "vmpc")]
use tc_rc4_family::{VmpcEngine, VmpcKsa3Engine};

use super::compose::boxed;
use super::specs::{Need, StreamSpec};

// A key of 1 to 256 bytes and no IV. The names and the OID follow Bouncy Castle
#[cfg(feature = "rc4")]
pub(super) const ARC4: StreamSpec = StreamSpec {
    names: &["ARC4", "RC4", "ARCFOUR"],
    iv: Need::Forbidden,
    create: || boxed(BufferedStreamCipher::new(Rc4Engine::new())),
    oids: &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x04],
        "1.2.840.113549.3.4",
        "rc4",
    )],
};

// A key and an IV of 16 to 64 bytes each
#[cfg(feature = "vmpc")]
pub(super) const VMPC: StreamSpec = StreamSpec {
    names: &["VMPC"],
    iv: Need::Required,
    create: || boxed(BufferedStreamCipher::new(VmpcEngine::new())),
    oids: &[],
};

#[cfg(feature = "vmpc")]
pub(super) const VMPC_KSA3: StreamSpec = StreamSpec {
    names: &["VMPC-KSA3"],
    iv: Need::Required,
    create: || boxed(BufferedStreamCipher::new(VmpcKsa3Engine::new())),
    oids: &[],
};
