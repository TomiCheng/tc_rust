use tc_asn1::NamedOid;
use tc_des::DesEdeEngine;

use super::specs::{AlgorithmSpec, ModeKind, PaddingKind};
use crate::cipher::engine::AnyEngine;

// A two- or three-key Triple DES key, 16 or 24 bytes; TDEA is Bouncy Castle's alias. The OIDs
// follow Bouncy Castle: OIW's desEDE has no mode, so it gives ECB
pub(super) const DESEDE: AlgorithmSpec = AlgorithmSpec {
    names: &["DESEDE", "TDEA"],
    block_size: 8,
    engine: || AnyEngine::new(DesEdeEngine::new()),
    oids: &[
        (
            ModeKind::Ecb,
            PaddingKind::Pkcs7,
            &[NamedOid::new(
                &[0x2b, 0x0e, 0x03, 0x02, 0x11],
                "1.3.14.3.2.17",
                "desEDE",
            )],
        ),
        (
            ModeKind::Cbc,
            PaddingKind::Pkcs7,
            &[NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07],
                "1.2.840.113549.3.7",
                "des-ede3-cbc",
            )],
        ),
    ],
};
