use tc_asn1::NamedOid;
use tc_camellia::CamelliaEngine;

use super::specs::{AlgorithmSpec, ModeKind, PaddingKind};
use crate::cipher::engine::AnyEngine;

// The NTT Camellia-CBC OIDs sit under 1.2.392.200011.61.1.1.1 and differ only in the last arc
macro_rules! ntt_camellia {
    ($arc:literal, $dotted:literal, $name:literal) => {
        NamedOid::new(
            &[
                0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x01, $arc,
            ],
            $dotted,
            $name,
        )
    };
}

// The OIDs follow Bouncy Castle, CBC alone
pub(super) const CAMELLIA: AlgorithmSpec = AlgorithmSpec {
    names: &["CAMELLIA"],
    block_size: 16,
    engine: || AnyEngine::new(CamelliaEngine::new()),
    oids: &[(
        ModeKind::Cbc,
        PaddingKind::Pkcs7,
        &[
            ntt_camellia!(0x02, "1.2.392.200011.61.1.1.1.2", "id-camellia128-cbc"),
            ntt_camellia!(0x03, "1.2.392.200011.61.1.1.1.3", "id-camellia192-cbc"),
            ntt_camellia!(0x04, "1.2.392.200011.61.1.1.1.4", "id-camellia256-cbc"),
        ],
    )],
};
