use tc_asn1::NamedOid;
use tc_seed::SeedEngine;

use super::specs::{AlgorithmSpec, ModeKind, PaddingKind};
use crate::cipher::engine::AnyEngine;

// The OID follows Bouncy Castle, CBC alone
pub(super) const SEED: AlgorithmSpec = AlgorithmSpec {
    names: &["SEED"],
    block_size: 16,
    engine: || AnyEngine::new(SeedEngine::new()),
    oids: &[(
        ModeKind::Cbc,
        PaddingKind::Pkcs7,
        &[NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x44, 0x01, 0x04],
            "1.2.410.200004.1.4",
            "id-seedCBC",
        )],
    )],
};
