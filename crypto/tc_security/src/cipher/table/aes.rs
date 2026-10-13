use tc_aes::AesEngine;
use tc_asn1::NamedOid;

use super::specs::{AlgorithmSpec, Lengths};
use crate::cipher::any_engine::AnyEngine;
use crate::cipher::{Algorithm, Mode, Padding};

// NIST 的 AES OID 都在 2.16.840.1.101.3.4.1 底下，只差最後一個 arc
macro_rules! nist_aes {
    ($arc:literal, $dotted:literal, $name:literal) => {
        NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, $arc],
            $dotted,
            $name,
        )
    };
}

/// 金鑰 16、24、32 bytes，沒給時產生 24 bytes（同 BC 的 192 bits）。
/// OID 照 BC：三種金鑰長度的 OID 對到同一個組合，不限制金鑰長度。
pub(super) const AES: AlgorithmSpec = AlgorithmSpec {
    algorithm: Algorithm::Aes,
    names: &["AES"],
    block_size: 16,
    key: Lengths::new(16, 32, 8, 24),
    engine: || AnyEngine::new(AesEngine::new()),
    oids: &[
        (
            Mode::Ecb,
            Padding::Pkcs7,
            &[
                nist_aes!(0x01, "2.16.840.1.101.3.4.1.1", "id-aes128-ECB"),
                nist_aes!(0x15, "2.16.840.1.101.3.4.1.21", "id-aes192-ECB"),
                nist_aes!(0x29, "2.16.840.1.101.3.4.1.41", "id-aes256-ECB"),
            ],
        ),
        (
            Mode::Cbc,
            Padding::Pkcs7,
            &[
                nist_aes!(0x02, "2.16.840.1.101.3.4.1.2", "id-aes128-CBC"),
                nist_aes!(0x16, "2.16.840.1.101.3.4.1.22", "id-aes192-CBC"),
                nist_aes!(0x2a, "2.16.840.1.101.3.4.1.42", "id-aes256-CBC"),
            ],
        ),
        (
            Mode::Ofb,
            Padding::NoPadding,
            &[
                nist_aes!(0x03, "2.16.840.1.101.3.4.1.3", "id-aes128-OFB"),
                nist_aes!(0x17, "2.16.840.1.101.3.4.1.23", "id-aes192-OFB"),
                nist_aes!(0x2b, "2.16.840.1.101.3.4.1.43", "id-aes256-OFB"),
            ],
        ),
        (
            Mode::Cfb,
            Padding::NoPadding,
            &[
                nist_aes!(0x04, "2.16.840.1.101.3.4.1.4", "id-aes128-CFB"),
                nist_aes!(0x18, "2.16.840.1.101.3.4.1.24", "id-aes192-CFB"),
                nist_aes!(0x2c, "2.16.840.1.101.3.4.1.44", "id-aes256-CFB"),
            ],
        ),
        (
            Mode::Gcm,
            Padding::NoPadding,
            &[
                nist_aes!(0x06, "2.16.840.1.101.3.4.1.6", "id-aes128-GCM"),
                nist_aes!(0x1a, "2.16.840.1.101.3.4.1.26", "id-aes192-GCM"),
                nist_aes!(0x2e, "2.16.840.1.101.3.4.1.46", "id-aes256-GCM"),
            ],
        ),
        (
            Mode::Ccm,
            Padding::NoPadding,
            &[
                nist_aes!(0x07, "2.16.840.1.101.3.4.1.7", "id-aes128-CCM"),
                nist_aes!(0x1b, "2.16.840.1.101.3.4.1.27", "id-aes192-CCM"),
                nist_aes!(0x2f, "2.16.840.1.101.3.4.1.47", "id-aes256-CCM"),
            ],
        ),
    ],
};
