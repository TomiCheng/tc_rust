use tc_asn1::NamedOid;
use tc_camellia::CamelliaEngine;

use super::specs::{AlgorithmSpec, Lengths};
use crate::cipher::any_engine::AnyEngine;
use crate::cipher::{Algorithm, Mode, Padding};

/// 金鑰 16、24、32 bytes，沒給時產生 32 bytes（同 BC 的 256 bits）。
/// OID 照 BC 只有 NTT 的三個 CBC，三種金鑰長度都對到 `CAMELLIA/CBC/PKCS7PADDING`，不限制金鑰長度。
/// tc_camellia 的引擎都不是常數時間（查表會依金鑰與資料存取記憶體）。
pub(super) const CAMELLIA: AlgorithmSpec = AlgorithmSpec {
    algorithm: Algorithm::Camellia,
    names: &["CAMELLIA"],
    block_size: tc_camellia::BLOCK_BYTES,
    key: Lengths::new(16, 32, 8, 32),
    engine: || AnyEngine::new(CamelliaEngine::new()),
    oids: &[(
        Mode::Cbc,
        Padding::Pkcs7,
        &[
            NamedOid::new(
                &[
                    0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x01, 0x02,
                ],
                "1.2.392.200011.61.1.1.1.2",
                "id-camellia128-cbc",
            ),
            NamedOid::new(
                &[
                    0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x01, 0x03,
                ],
                "1.2.392.200011.61.1.1.1.3",
                "id-camellia192-cbc",
            ),
            NamedOid::new(
                &[
                    0x2a, 0x83, 0x08, 0x8c, 0x9a, 0x4b, 0x3d, 0x01, 0x01, 0x01, 0x04,
                ],
                "1.2.392.200011.61.1.1.1.4",
                "id-camellia256-cbc",
            ),
        ],
    )],
};
