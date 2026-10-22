#[allow(
    unused_imports,
    reason = "所有 agreement 的 feature 都關掉時，表是空的"
)]
use tc_asn1::NamedOid;

use super::AgreementEntry;
#[allow(
    unused_imports,
    reason = "所有 agreement 的 feature 都關掉時，表是空的"
)]
use super::AnyAgreement;
#[allow(
    unused_imports,
    reason = "所有 agreement 的 feature 都關掉時，表是空的"
)]
use crate::params::AnyParams;

/// 每種 agreement 一列；新增時在這裡加一列。
pub(super) const AGREEMENTS: &[AgreementEntry] = &[
    // RFC 7748；OID 照 RFC 8410
    #[cfg(feature = "x25519")]
    AgreementEntry::new(
        &["X25519"],
        &[NamedOid::new(
            &[0x2b, 0x65, 0x6e],
            "1.3.101.110",
            "id-X25519",
        )],
        || {
            AnyAgreement::new(
                tc_cfrg_curves::X25519Agreement::new(),
                |params| match params {
                    AnyParams::X25519Private { key } => Some(key),
                    _ => None,
                },
                |params| match params {
                    AnyParams::X25519Public { key } => Some(key),
                    _ => None,
                },
            )
        },
    ),
    #[cfg(feature = "x448")]
    AgreementEntry::new(
        &["X448"],
        &[NamedOid::new(&[0x2b, 0x65, 0x6f], "1.3.101.111", "id-X448")],
        || {
            AnyAgreement::new(
                tc_cfrg_curves::X448Agreement::new(),
                |params| match params {
                    AnyParams::X448Private { key } => Some(key),
                    _ => None,
                },
                |params| match params {
                    AnyParams::X448Public { key } => Some(key),
                    _ => None,
                },
            )
        },
    ),
];
