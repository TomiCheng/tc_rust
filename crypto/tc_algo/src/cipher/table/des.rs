use tc_asn1::NamedOid;
use tc_des::DesEngine;

use super::specs::{AlgorithmSpec, ModeKind, PaddingKind};
use crate::cipher::engine::AnyEngine;

// The OIW DES OIDs sit under 1.3.14.3.2 and differ only in the last arc
macro_rules! oiw_des {
    ($arc:literal, $dotted:literal, $name:literal) => {
        NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, $arc], $dotted, $name)
    };
}

// The OIDs follow Bouncy Castle, each on the mode with its default padding
pub(super) const DES: AlgorithmSpec = AlgorithmSpec {
    names: &["DES"],
    block_size: 8,
    engine: || AnyEngine::new(DesEngine::new()),
    oids: &[
        (
            ModeKind::Ecb,
            PaddingKind::Pkcs7,
            &[oiw_des!(0x06, "1.3.14.3.2.6", "desECB")],
        ),
        (
            ModeKind::Cbc,
            PaddingKind::Pkcs7,
            &[oiw_des!(0x07, "1.3.14.3.2.7", "desCBC")],
        ),
        (
            ModeKind::Ofb,
            PaddingKind::NoPadding,
            &[oiw_des!(0x08, "1.3.14.3.2.8", "desOFB")],
        ),
        (
            ModeKind::Cfb,
            PaddingKind::NoPadding,
            &[oiw_des!(0x09, "1.3.14.3.2.9", "desCFB")],
        ),
    ],
};
