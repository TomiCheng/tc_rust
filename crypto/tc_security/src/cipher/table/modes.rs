use super::specs::ModeSpec;
use crate::cipher::Mode;

/// 各模式能搭配的區塊大小與 padding 規則；IV 與 tag 的長度由模式自己在 `init` 檢查。
pub(super) const MODES: &[ModeSpec] = &[
    ModeSpec {
        mode: Mode::Ecb,
        names: &["ECB"],
        aead: false,
        block_sizes: &[],
        partial_block: false,
    },
    ModeSpec {
        mode: Mode::Cbc,
        names: &["CBC"],
        aead: false,
        block_sizes: &[],
        partial_block: false,
    },
    ModeSpec {
        mode: Mode::Cfb,
        names: &["CFB"],
        aead: false,
        block_sizes: &[],
        partial_block: true,
    },
    ModeSpec {
        mode: Mode::Ofb,
        names: &["OFB"],
        aead: false,
        block_sizes: &[],
        partial_block: true,
    },
    ModeSpec {
        mode: Mode::Ctr,
        names: &["CTR", "SIC"],
        aead: false,
        block_sizes: &[],
        partial_block: true,
    },
    ModeSpec {
        mode: Mode::Ccm,
        names: &["CCM"],
        aead: true,
        block_sizes: &[16],
        partial_block: false,
    },
    ModeSpec {
        mode: Mode::Eax,
        names: &["EAX"],
        aead: true,
        block_sizes: &[8, 16],
        partial_block: false,
    },
    ModeSpec {
        mode: Mode::Gcm,
        names: &["GCM"],
        aead: true,
        block_sizes: &[16],
        partial_block: false,
    },
    ModeSpec {
        mode: Mode::Ocb,
        names: &["OCB"],
        aead: true,
        block_sizes: &[16],
        partial_block: false,
    },
];
