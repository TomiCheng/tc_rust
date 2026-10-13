use tc_aria::AriaEngine;
use tc_asn1::NamedOid;

use super::specs::{AlgorithmSpec, Lengths};
use crate::cipher::any_engine::AnyEngine;
use crate::cipher::{Algorithm, Mode, Padding};

// NSRI 的 ARIA OID 都在 1.2.410.200046.1.1 底下，只差最後一個 arc
macro_rules! nsri_aria {
    ($arc:literal, $dotted:literal, $name:literal) => {
        NamedOid::new(
            &[0x2a, 0x83, 0x1a, 0x8c, 0x9a, 0x6e, 0x01, 0x01, $arc],
            $dotted,
            $name,
        )
    };
}

/// 金鑰 16、24、32 bytes，沒給時產生 32 bytes（同 BC 的 256 bits）。
/// OID 照 BC：三種金鑰長度的 OID 對到同一個組合，不限制金鑰長度。
/// tc_aria 的引擎都不是常數時間（查表會依金鑰與資料存取記憶體）。
pub(super) const ARIA: AlgorithmSpec = AlgorithmSpec {
    algorithm: Algorithm::Aria,
    names: &["ARIA"],
    block_size: 16,
    key: Lengths::new(16, 32, 8, 32),
    engine: || AnyEngine::new(AriaEngine::new()),
    oids: &[
        (
            Mode::Ecb,
            Padding::Pkcs7,
            &[
                nsri_aria!(0x01, "1.2.410.200046.1.1.1", "aria128-ecb"),
                nsri_aria!(0x06, "1.2.410.200046.1.1.6", "aria192-ecb"),
                nsri_aria!(0x0b, "1.2.410.200046.1.1.11", "aria256-ecb"),
            ],
        ),
        (
            Mode::Cbc,
            Padding::Pkcs7,
            &[
                nsri_aria!(0x02, "1.2.410.200046.1.1.2", "aria128-cbc"),
                nsri_aria!(0x07, "1.2.410.200046.1.1.7", "aria192-cbc"),
                nsri_aria!(0x0c, "1.2.410.200046.1.1.12", "aria256-cbc"),
            ],
        ),
        (
            Mode::Cfb,
            Padding::NoPadding,
            &[
                nsri_aria!(0x03, "1.2.410.200046.1.1.3", "aria128-cfb"),
                nsri_aria!(0x08, "1.2.410.200046.1.1.8", "aria192-cfb"),
                nsri_aria!(0x0d, "1.2.410.200046.1.1.13", "aria256-cfb"),
            ],
        ),
        (
            Mode::Ofb,
            Padding::NoPadding,
            &[
                nsri_aria!(0x04, "1.2.410.200046.1.1.4", "aria128-ofb"),
                nsri_aria!(0x09, "1.2.410.200046.1.1.9", "aria192-ofb"),
                nsri_aria!(0x0e, "1.2.410.200046.1.1.14", "aria256-ofb"),
            ],
        ),
        (
            Mode::Ctr,
            Padding::NoPadding,
            &[
                nsri_aria!(0x05, "1.2.410.200046.1.1.5", "aria128-ctr"),
                nsri_aria!(0x0a, "1.2.410.200046.1.1.10", "aria192-ctr"),
                nsri_aria!(0x0f, "1.2.410.200046.1.1.15", "aria256-ctr"),
            ],
        ),
        (
            Mode::Gcm,
            Padding::NoPadding,
            &[
                nsri_aria!(0x22, "1.2.410.200046.1.1.34", "aria128-gcm"),
                nsri_aria!(0x23, "1.2.410.200046.1.1.35", "aria192-gcm"),
                nsri_aria!(0x24, "1.2.410.200046.1.1.36", "aria256-gcm"),
            ],
        ),
        (
            Mode::Ccm,
            Padding::NoPadding,
            &[
                nsri_aria!(0x25, "1.2.410.200046.1.1.37", "aria128-ccm"),
                nsri_aria!(0x26, "1.2.410.200046.1.1.38", "aria192-ccm"),
                nsri_aria!(0x27, "1.2.410.200046.1.1.39", "aria256-ccm"),
            ],
        ),
    ],
};
