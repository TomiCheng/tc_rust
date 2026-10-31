// RC2, RC5 and RC6, each behind its own feature. A bare key takes Bouncy Castle's defaults for
// the rest: as many effective bits as the key has for RC2, twelve rounds for RC5
#[cfg(feature = "rc2")]
use tc_asn1::NamedOid;

use super::specs::AlgorithmSpec;
#[cfg(feature = "rc2")]
use super::specs::{ModeKind, PaddingKind};
use crate::cipher::engine::AnyEngine;

#[cfg(feature = "rc2")]
pub(super) const RC2: AlgorithmSpec = AlgorithmSpec {
    names: &["RC2"],
    block_size: 8,
    engine: || AnyEngine::new(tc_rc_cipher::Rc2Engine::new()),
    oids: &[(
        ModeKind::Cbc,
        PaddingKind::Pkcs7,
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02],
            "1.2.840.113549.3.2",
            "rc2CBC",
        )],
    )],
};

// RC5-32: 32-bit words and 64-bit blocks. RC5-32 is Bouncy Castle's alias
#[cfg(feature = "rc5")]
pub(super) const RC5: AlgorithmSpec = AlgorithmSpec {
    names: &["RC5", "RC5-32"],
    block_size: 8,
    engine: || AnyEngine::new(tc_rc_cipher::Rc532Engine::new()),
    oids: &[],
};

// RC5-64: 64-bit words and 128-bit blocks
#[cfg(feature = "rc5-64")]
pub(super) const RC5_64: AlgorithmSpec = AlgorithmSpec {
    names: &["RC5-64"],
    block_size: 16,
    engine: || AnyEngine::new(tc_rc_cipher::Rc564Engine::new()),
    oids: &[],
};

#[cfg(feature = "rc6")]
pub(super) const RC6: AlgorithmSpec = AlgorithmSpec {
    names: &["RC6"],
    block_size: 16,
    engine: || AnyEngine::new(tc_rc_cipher::Rc6Engine::new()),
    oids: &[],
};
