//! DES 與 Triple DES：只為了和既有格式相容，新設計應改用 AES。
//! 引擎同 BC 忽略 parity bit、接受弱金鑰；產生金鑰時才避開它們（見 generate 的 des）。

use tc_asn1::NamedOid;
#[cfg(feature = "des")]
use tc_des::DesEngine;
#[cfg(feature = "desede")]
use tc_des::{DesEdeEngine, EDE2_KEY_BYTES, EDE3_KEY_BYTES};

use super::specs::{AlgorithmSpec, Lengths};
use crate::cipher::any_engine::AnyEngine;
use crate::cipher::{Algorithm, Mode, Padding};

/// 區塊 8 bytes，金鑰 8 bytes（含 parity bit）。OID 照 BC 是 OIW 的四個模式。
#[cfg(feature = "des")]
pub(super) const DES: AlgorithmSpec = AlgorithmSpec {
    algorithm: Algorithm::Des,
    names: &["DES"],
    block_size: tc_des::BLOCK_BYTES,
    key: Lengths::exact(8),
    engine: || AnyEngine::new(DesEngine::new()),
    oids: &[
        (
            Mode::Ecb,
            Padding::Pkcs7,
            &[NamedOid::new(
                &[0x2b, 0x0e, 0x03, 0x02, 0x06],
                "1.3.14.3.2.6",
                "desECB",
            )],
        ),
        (
            Mode::Cbc,
            Padding::Pkcs7,
            &[NamedOid::new(
                &[0x2b, 0x0e, 0x03, 0x02, 0x07],
                "1.3.14.3.2.7",
                "desCBC",
            )],
        ),
        (
            Mode::Ofb,
            Padding::NoPadding,
            &[NamedOid::new(
                &[0x2b, 0x0e, 0x03, 0x02, 0x08],
                "1.3.14.3.2.8",
                "desOFB",
            )],
        ),
        (
            Mode::Cfb,
            Padding::NoPadding,
            &[NamedOid::new(
                &[0x2b, 0x0e, 0x03, 0x02, 0x09],
                "1.3.14.3.2.9",
                "desCFB",
            )],
        ),
    ],
};

/// 區塊 8 bytes；金鑰 16 bytes（K1、K2、K1）或 24 bytes，沒給時產生 16 bytes（同 BC 的 128 bits）。
/// OID 照 BC：OIW 的 desEDE 對到 ECB，PKCS 的 des-ede3-cbc 對到 CBC。
#[cfg(feature = "desede")]
pub(super) const DESEDE: AlgorithmSpec = AlgorithmSpec {
    algorithm: Algorithm::DesEde,
    names: &["DESEDE", "TDEA"],
    block_size: tc_des::BLOCK_BYTES,
    key: Lengths::new(EDE2_KEY_BYTES, EDE3_KEY_BYTES, 8, EDE2_KEY_BYTES),
    engine: || AnyEngine::new(DesEdeEngine::new()),
    oids: &[
        (
            Mode::Ecb,
            Padding::Pkcs7,
            &[NamedOid::new(
                &[0x2b, 0x0e, 0x03, 0x02, 0x11],
                "1.3.14.3.2.17",
                "desEDE",
            )],
        ),
        (
            Mode::Cbc,
            Padding::Pkcs7,
            &[NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07],
                "1.2.840.113549.3.7",
                "des-ede3-cbc",
            )],
        ),
    ],
};
