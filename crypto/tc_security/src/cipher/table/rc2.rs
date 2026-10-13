//! RC2：只為了和既有格式相容，新設計應改用有驗證的 cipher。BC 產生金鑰時直接取亂數，沒有 weak key 要避開。

use tc_asn1::NamedOid;
use tc_rc_cipher::{RC2_MAX_KEY_BYTES, Rc2Engine};

use super::specs::{AlgorithmSpec, Lengths};
use crate::cipher::any_engine::AnyEngine;
use crate::cipher::{Algorithm, Mode, Padding};

/// 區塊 8 bytes；金鑰 1 到 128 bytes，沒給時產生 16 bytes（同 BC 的 128 bits）。
/// OID 照 BC 只有 RC2-CBC，對到 `RC2/CBC`（補 PKCS7）。
pub(super) const RC2: AlgorithmSpec = AlgorithmSpec {
    algorithm: Algorithm::Rc2,
    names: &["RC2"],
    block_size: 8,
    key: Lengths::new(1, RC2_MAX_KEY_BYTES, 1, 16),
    engine: || AnyEngine::new(Rc2Engine::new()),
    oids: &[(
        Mode::Cbc,
        Padding::Pkcs7,
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02],
            "1.2.840.113549.3.2",
            "rc2CBC",
        )],
    )],
};
