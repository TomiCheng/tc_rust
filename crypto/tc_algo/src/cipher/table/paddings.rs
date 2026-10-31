use super::specs::{PaddingKind, PaddingSpec};

// The names of Bouncy Castle, matched without regard to ASCII case
pub(super) static PADDINGS: &[PaddingSpec] = &[
    PaddingSpec {
        kind: PaddingKind::NoPadding,
        names: &["NOPADDING"],
    },
    PaddingSpec {
        kind: PaddingKind::Pkcs7,
        names: &["PKCS7PADDING", "PKCS7", "PKCS5PADDING", "PKCS5"],
    },
    PaddingSpec {
        kind: PaddingKind::Iso10126,
        names: &["ISO10126PADDING", "ISO10126D2PADDING", "ISO10126-2PADDING"],
    },
    PaddingSpec {
        kind: PaddingKind::Iso7816,
        names: &["ISO7816-4PADDING", "ISO9797-1PADDING"],
    },
    PaddingSpec {
        kind: PaddingKind::X923,
        names: &["X923PADDING"],
    },
    PaddingSpec {
        kind: PaddingKind::Tbc,
        names: &["TBCPADDING"],
    },
    PaddingSpec {
        kind: PaddingKind::ZeroByte,
        names: &["ZEROBYTEPADDING"],
    },
];
