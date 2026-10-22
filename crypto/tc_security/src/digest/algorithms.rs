use tc_asn1::Asn1Oid;

use super::table::DIGESTS;
use super::{Algorithm, AnyDigest, DigestEntry};
use crate::SecurityError;

pub fn algorithms() -> impl Iterator<Item = &'static DigestEntry> {
    DIGESTS.iter().filter(|entry| !disabled(entry))
}

/// 用 enum 指定一定認得，所以不會失敗。不受 env 開關影響：程式明確指定的演算法照樣建立。
pub fn get(algorithm: Algorithm) -> AnyDigest {
    algorithm.entry().create()
}

/// 名稱比對不分大小寫；不是名稱時改當點分 OID 解析，同 BC。同樣不受 env 開關影響。
pub fn get_by_name(name: &str) -> Result<AnyDigest, SecurityError> {
    find(name)
        .map(DigestEntry::create)
        .ok_or(SecurityError::UnknownDigest)
}

/// 同樣不受 env 開關影響。
pub fn get_by_oid(oid: &Asn1Oid) -> Result<AnyDigest, SecurityError> {
    find_by_oid(oid)
        .map(DigestEntry::create)
        .ok_or(SecurityError::UnknownDigest)
}

fn find(name: &str) -> Option<&'static DigestEntry> {
    DIGESTS
        .iter()
        .find(|entry| {
            entry
                .names()
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })
        .or_else(|| find_by_oid(&name.parse().ok()?))
}

fn find_by_oid(oid: &Asn1Oid) -> Option<&'static DigestEntry> {
    DIGESTS
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}

/// 弱點揭露後、修補前的緊急開關：列在這裡的 digest 不出現在清單，但仍可直接建立。
const DISABLED_ENV: &str = "TC_SECURITY_DISABLED_DIGESTS";

fn disabled(entry: &DigestEntry) -> bool {
    use std::sync::OnceLock;

    // 第一次用到時讀一次，之後不再變動
    static DISABLED: OnceLock<Option<String>> = OnceLock::new();
    DISABLED
        .get_or_init(|| std::env::var(DISABLED_ENV).ok())
        .as_deref()
        .is_some_and(|list| list.split(',').any(|name| find(name.trim()) == Some(entry)))
}
