use super::specs::{AsymmetricPaddingKind, AsymmetricPaddingSpec};

// An asymmetric cipher has no mode; as in Bouncy Castle, a name may still give ECB, or leave the
// mode out. The first is the canonical name
pub(super) const ASYMMETRIC_MODE_NAMES: &[&str] = &["NONE", "ECB"];

// The names of Bouncy Castle, matched without regard to ASCII case and with '-' and '_' the same.
// OAEPPADDING is OAEP with SHA-1, as id-RSAES-OAEP has it by default. NoPadding comes first: it
// is what a name without a padding gives
pub(super) static ASYMMETRIC_PADDINGS: &[AsymmetricPaddingSpec] = &[
    AsymmetricPaddingSpec {
        kind: AsymmetricPaddingKind::NoPadding,
        names: &["NOPADDING"],
    },
    AsymmetricPaddingSpec {
        kind: AsymmetricPaddingKind::Pkcs1,
        names: &["PKCS1PADDING", "PKCS1"],
    },
    #[cfg(feature = "rsa-iso9796")]
    AsymmetricPaddingSpec {
        kind: AsymmetricPaddingKind::Iso9796d1,
        names: &["ISO9796-1PADDING", "ISO9796-1"],
    },
    #[cfg(feature = "md5")]
    AsymmetricPaddingSpec {
        kind: AsymmetricPaddingKind::OaepMd5,
        names: &["OAEPWITHMD5ANDMGF1PADDING"],
    },
    AsymmetricPaddingSpec {
        kind: AsymmetricPaddingKind::OaepSha1,
        names: &[
            "OAEPWITHSHA1ANDMGF1PADDING",
            "OAEPWITHSHA-1ANDMGF1PADDING",
            "OAEPPADDING",
            "OAEP",
        ],
    },
    AsymmetricPaddingSpec {
        kind: AsymmetricPaddingKind::OaepSha224,
        names: &[
            "OAEPWITHSHA224ANDMGF1PADDING",
            "OAEPWITHSHA-224ANDMGF1PADDING",
        ],
    },
    AsymmetricPaddingSpec {
        kind: AsymmetricPaddingKind::OaepSha256,
        names: &[
            "OAEPWITHSHA256ANDMGF1PADDING",
            "OAEPWITHSHA-256ANDMGF1PADDING",
            "OAEPWITHSHA256ANDMGF1WITHSHA256PADDING",
            "OAEPWITHSHA-256ANDMGF1WITHSHA-256PADDING",
        ],
    },
    AsymmetricPaddingSpec {
        kind: AsymmetricPaddingKind::OaepSha256Mgf1Sha1,
        names: &[
            "OAEPWITHSHA256ANDMGF1WITHSHA1PADDING",
            "OAEPWITHSHA-256ANDMGF1WITHSHA-1PADDING",
        ],
    },
    AsymmetricPaddingSpec {
        kind: AsymmetricPaddingKind::OaepSha384,
        names: &[
            "OAEPWITHSHA384ANDMGF1PADDING",
            "OAEPWITHSHA-384ANDMGF1PADDING",
        ],
    },
    AsymmetricPaddingSpec {
        kind: AsymmetricPaddingKind::OaepSha512,
        names: &[
            "OAEPWITHSHA512ANDMGF1PADDING",
            "OAEPWITHSHA-512ANDMGF1PADDING",
        ],
    },
];
