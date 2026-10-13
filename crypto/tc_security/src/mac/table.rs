#[allow(unused_imports, reason = "所有 MAC 的 feature 都關掉時，表是空的")]
use tc_asn1::NamedOid;

#[allow(unused_imports, reason = "所有 MAC 的 feature 都關掉時，表是空的")]
use super::AnyMac;
use super::MacEntry;

/// 每種 MAC 一列；新增時在這裡加一列。
pub(super) const MACS: &[MacEntry] = &[
    // HMAC 接受任意長度的金鑰；沒給時產生跟 digest 輸出一樣長的 28 bytes（同 BC 的 224 bits）。
    // 別名照 BC 的寫法：HMAC 與 digest 名稱之間可以是 `-`、`/` 或什麼都沒有
    #[cfg(feature = "sha224")]
    MacEntry::new(
        &["HMAC-SHA224", "HMAC/SHA224", "HMACSHA224"],
        &[NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08],
            "1.2.840.113549.2.8",
            "id-hmacWithSHA224",
        )],
        1,
        usize::MAX,
        28,
        || {
            AnyMac::new(tc_macs::Hmac::new(crate::digest::get(
                crate::digest::Algorithm::Sha224,
            )))
        },
    ),
    // CBC-MAC 套在 RC2 上，tag 同 BC 是半個區塊（4 bytes），最後不滿一塊時補零。
    // 金鑰 1 到 128 bytes，產生時 16 bytes（同 BC 的 128 bits）；參數沒帶 IV 時同 BC 用全零的 8 bytes
    #[cfg(feature = "rc2")]
    MacEntry::new(
        &["RC2MAC", "RC2"],
        &[],
        1,
        tc_rc_cipher::RC2_MAX_KEY_BYTES,
        16,
        || {
            AnyMac::new(super::ZeroIv::new(
                tc_macs::CbcMac::new(tc_rc_cipher::Rc2Engine::new()),
                8,
            ))
        },
    ),
];
