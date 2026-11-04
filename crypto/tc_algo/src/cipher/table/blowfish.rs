use tc_asn1::NamedOid;
use tc_blowfish::BlowfishEngine;

use super::specs::{AlgorithmSpec, ModeKind, PaddingKind};
use crate::cipher::engine::AnyEngine;

// Bouncy Castle maps cryptlib's Blowfish-CBC OID and, for old data, a wrong version of it that
// lacks an arc
pub(super) const BLOWFISH: AlgorithmSpec = AlgorithmSpec {
    names: &["BLOWFISH"],
    block_size: 8,
    engine: || AnyEngine::new(BlowfishEngine::new()),
    oids: &[(
        ModeKind::Cbc,
        PaddingKind::Pkcs7,
        &[
            NamedOid::new(
                &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x01, 0x02],
                "1.3.6.1.4.1.3029.1.1.2",
                "blowfishCBC",
            ),
            NamedOid::new(
                &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x02],
                "1.3.6.1.4.1.3029.1.2",
                "blowfishCBC (wrong version)",
            ),
        ],
    )],
};
