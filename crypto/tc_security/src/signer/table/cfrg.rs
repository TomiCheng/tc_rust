//! RFC 8032 的 EdDSA。名稱、OID 與空的 context 照 BC 的 `SignerUtilities`。

use tc_asn1::NamedOid;
use tc_cfrg_curves::CfrgError;
use tc_signer::{Signer, SignerInit};

use crate::params::AnyParams;
use crate::signer::{AnySigner, SignerEntry};

// 私鑰簽章、公鑰驗章，兩種金鑰型別不同
#[cfg(feature = "ed25519")]
fn ed25519<T>(signer: T) -> AnySigner
where
    T: Signer<Error = CfrgError>
        + SignerInit<tc_cfrg_curves::Ed25519PrivateKey, Error = CfrgError>
        + SignerInit<tc_cfrg_curves::Ed25519PublicKey, Error = CfrgError>
        + 'static,
{
    AnySigner::new(
        signer,
        |params| match params {
            AnyParams::Ed25519Private { key } => Some(key),
            _ => None,
        },
        |params| match params {
            AnyParams::Ed25519Public { key } => Some(key),
            _ => None,
        },
    )
}

#[cfg(feature = "ed448")]
fn ed448<T>(signer: T) -> AnySigner
where
    T: Signer<Error = CfrgError>
        + SignerInit<tc_cfrg_curves::Ed448PrivateKey, Error = CfrgError>
        + SignerInit<tc_cfrg_curves::Ed448PublicKey, Error = CfrgError>
        + 'static,
{
    AnySigner::new(
        signer,
        |params| match params {
            AnyParams::Ed448Private { key } => Some(key),
            _ => None,
        },
        |params| match params {
            AnyParams::Ed448Public { key } => Some(key),
            _ => None,
        },
    )
}

#[cfg(feature = "ed25519")]
pub(super) const ED25519: SignerEntry = SignerEntry::new(
    &["Ed25519"],
    &[NamedOid::new(
        &[0x2b, 0x65, 0x70],
        "1.3.101.112",
        "id-Ed25519",
    )],
    || ed25519(tc_cfrg_curves::Ed25519Signer::new()),
);

#[cfg(feature = "ed25519")]
pub(super) const ED25519CTX: SignerEntry = SignerEntry::new(&["Ed25519ctx"], &[], || {
    ed25519(tc_cfrg_curves::Ed25519CtxSigner::new(&[]))
});

#[cfg(feature = "ed25519")]
pub(super) const ED25519PH: SignerEntry = SignerEntry::new(&["Ed25519ph"], &[], || {
    ed25519(tc_cfrg_curves::Ed25519PhSigner::new(&[]))
});

#[cfg(feature = "ed448")]
pub(super) const ED448: SignerEntry = SignerEntry::new(
    &["Ed448"],
    &[NamedOid::new(
        &[0x2b, 0x65, 0x71],
        "1.3.101.113",
        "id-Ed448",
    )],
    || ed448(tc_cfrg_curves::Ed448Signer::new(&[])),
);

#[cfg(feature = "ed448")]
pub(super) const ED448PH: SignerEntry = SignerEntry::new(&["Ed448ph"], &[], || {
    ed448(tc_cfrg_curves::Ed448PhSigner::new(&[]))
});
