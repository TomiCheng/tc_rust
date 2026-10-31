use super::specs::{ModeKind, ModeSpec};

// The block sizes each mode runs on; the IV and tag lengths are checked by the mode in init
pub(super) static MODES: &[ModeSpec] = &[
    ModeSpec {
        kind: ModeKind::Ecb,
        names: &["ECB"],
        aead: false,
        block_sizes: &[],
        partial_block: false,
    },
    ModeSpec {
        kind: ModeKind::Cbc,
        names: &["CBC"],
        aead: false,
        block_sizes: &[],
        partial_block: false,
    },
    ModeSpec {
        kind: ModeKind::Cfb,
        names: &["CFB"],
        aead: false,
        block_sizes: &[],
        partial_block: true,
    },
    ModeSpec {
        kind: ModeKind::Ofb,
        names: &["OFB"],
        aead: false,
        block_sizes: &[],
        partial_block: true,
    },
    ModeSpec {
        kind: ModeKind::Ctr,
        names: &["CTR", "SIC"],
        aead: false,
        block_sizes: &[],
        partial_block: true,
    },
    ModeSpec {
        kind: ModeKind::Ccm,
        names: &["CCM"],
        aead: true,
        block_sizes: &[16],
        partial_block: false,
    },
    ModeSpec {
        kind: ModeKind::Eax,
        names: &["EAX"],
        aead: true,
        block_sizes: &[8, 16],
        partial_block: false,
    },
    ModeSpec {
        kind: ModeKind::Gcm,
        names: &["GCM"],
        aead: true,
        block_sizes: &[16],
        partial_block: false,
    },
    ModeSpec {
        kind: ModeKind::Ocb,
        names: &["OCB"],
        aead: true,
        block_sizes: &[16],
        partial_block: false,
    },
];
