// The block ciphers of tc_misc_block_cipher, each behind its own feature
#[cfg(feature = "idea")]
use tc_asn1::NamedOid;

use super::specs::AlgorithmSpec;
#[cfg(feature = "idea")]
use super::specs::{ModeKind, PaddingKind};
use crate::cipher::engine::AnyEngine;

#[cfg(feature = "idea")]
pub(super) const IDEA: AlgorithmSpec = AlgorithmSpec {
    names: &["IDEA"],
    block_size: 8,
    engine: || AnyEngine::new(tc_misc_block_cipher::idea::IdeaEngine::new()),
    oids: &[(
        ModeKind::Cbc,
        PaddingKind::Pkcs7,
        &[NamedOid::new(
            &[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x3c, 0x07, 0x01, 0x01, 0x02,
            ],
            "1.3.6.1.4.1.188.7.1.1.2",
            "IDEA-CBC",
        )],
    )],
};

#[cfg(feature = "noekeon")]
pub(super) const NOEKEON: AlgorithmSpec = AlgorithmSpec {
    names: &["NOEKEON"],
    block_size: 16,
    engine: || AnyEngine::new(tc_misc_block_cipher::noekeon::NoekeonEngine::new()),
    oids: &[],
};

// Rijndael of 128-bit blocks, as Bouncy Castle's factory builds it
#[cfg(feature = "rijndael")]
pub(super) const RIJNDAEL: AlgorithmSpec = AlgorithmSpec {
    names: &["RIJNDAEL"],
    block_size: 16,
    engine: || AnyEngine::new(tc_misc_block_cipher::rijndael::Rijndael128Engine::new()),
    oids: &[],
};

#[cfg(feature = "skipjack")]
pub(super) const SKIPJACK: AlgorithmSpec = AlgorithmSpec {
    names: &["SKIPJACK"],
    block_size: 8,
    engine: || AnyEngine::new(tc_misc_block_cipher::skipjack::SkipjackEngine::new()),
    oids: &[],
};

#[cfg(feature = "tea")]
pub(super) const TEA: AlgorithmSpec = AlgorithmSpec {
    names: &["TEA"],
    block_size: 8,
    engine: || AnyEngine::new(tc_misc_block_cipher::tea::TeaEngine::new()),
    oids: &[],
};

#[cfg(feature = "xtea")]
pub(super) const XTEA: AlgorithmSpec = AlgorithmSpec {
    names: &["XTEA"],
    block_size: 8,
    engine: || AnyEngine::new(tc_misc_block_cipher::tea::XteaEngine::new()),
    oids: &[],
};
