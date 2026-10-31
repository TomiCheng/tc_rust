use tc_asn1::NamedOid;
use tc_gost28147::Gost28147Engine;

use super::specs::{AlgorithmSpec, ModeKind, PaddingKind};
use crate::cipher::engine::AnyEngine;

// With Bouncy Castle's default S-box. Bouncy Castle maps the OID of GOST 28147-89, whose own
// mode is CFB with key meshing, to CBC with PKCS7 padding, and so does this table
pub(super) const GOST28147: AlgorithmSpec = AlgorithmSpec {
    names: &["GOST28147", "GOST", "GOST-28147"],
    block_size: 8,
    engine: || AnyEngine::new(Gost28147Engine::new()),
    oids: &[(
        ModeKind::Cbc,
        PaddingKind::Pkcs7,
        &[NamedOid::new(
            &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x15],
            "1.2.643.2.2.21",
            "id-Gost28147-89",
        )],
    )],
};
