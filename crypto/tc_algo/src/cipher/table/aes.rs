use tc_aes::AesEngine;
use tc_asn1::NamedOid;

use super::specs::{AlgorithmSpec, ModeKind, PaddingKind};
use crate::cipher::engine::AnyEngine;

// The NIST AES OIDs sit under 2.16.840.1.101.3.4.1 and differ only in the last arc
macro_rules! nist_aes {
    ($arc:literal, $dotted:literal, $name:literal) => {
        NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, $arc],
            $dotted,
            $name,
        )
    };
}

// The OIDs follow Bouncy Castle: the OIDs of the three key sizes come to the same combination,
// which takes any AES key size
pub(super) const AES: AlgorithmSpec = AlgorithmSpec {
    names: &["AES"],
    block_size: 16,
    engine: || AnyEngine::new(AesEngine::new()),
    oids: &[
        (
            ModeKind::Ecb,
            PaddingKind::Pkcs7,
            &[
                nist_aes!(0x01, "2.16.840.1.101.3.4.1.1", "id-aes128-ECB"),
                nist_aes!(0x15, "2.16.840.1.101.3.4.1.21", "id-aes192-ECB"),
                nist_aes!(0x29, "2.16.840.1.101.3.4.1.41", "id-aes256-ECB"),
            ],
        ),
        (
            ModeKind::Cbc,
            PaddingKind::Pkcs7,
            &[
                nist_aes!(0x02, "2.16.840.1.101.3.4.1.2", "id-aes128-CBC"),
                nist_aes!(0x16, "2.16.840.1.101.3.4.1.22", "id-aes192-CBC"),
                nist_aes!(0x2a, "2.16.840.1.101.3.4.1.42", "id-aes256-CBC"),
            ],
        ),
        (
            ModeKind::Ofb,
            PaddingKind::NoPadding,
            &[
                nist_aes!(0x03, "2.16.840.1.101.3.4.1.3", "id-aes128-OFB"),
                nist_aes!(0x17, "2.16.840.1.101.3.4.1.23", "id-aes192-OFB"),
                nist_aes!(0x2b, "2.16.840.1.101.3.4.1.43", "id-aes256-OFB"),
            ],
        ),
        (
            ModeKind::Cfb,
            PaddingKind::NoPadding,
            &[
                nist_aes!(0x04, "2.16.840.1.101.3.4.1.4", "id-aes128-CFB"),
                nist_aes!(0x18, "2.16.840.1.101.3.4.1.24", "id-aes192-CFB"),
                nist_aes!(0x2c, "2.16.840.1.101.3.4.1.44", "id-aes256-CFB"),
            ],
        ),
        (
            ModeKind::Gcm,
            PaddingKind::NoPadding,
            &[
                nist_aes!(0x06, "2.16.840.1.101.3.4.1.6", "id-aes128-GCM"),
                nist_aes!(0x1a, "2.16.840.1.101.3.4.1.26", "id-aes192-GCM"),
                nist_aes!(0x2e, "2.16.840.1.101.3.4.1.46", "id-aes256-GCM"),
            ],
        ),
        (
            ModeKind::Ccm,
            PaddingKind::NoPadding,
            &[
                nist_aes!(0x07, "2.16.840.1.101.3.4.1.7", "id-aes128-CCM"),
                nist_aes!(0x1b, "2.16.840.1.101.3.4.1.27", "id-aes192-CCM"),
                nist_aes!(0x2f, "2.16.840.1.101.3.4.1.47", "id-aes256-CCM"),
            ],
        ),
    ],
};
