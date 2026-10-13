use tc_asn1::NamedOid;

use crate::cipher::any_engine::AnyEngine;
use crate::cipher::{Algorithm, AnyCipher, Mode, Padding};

/// 可接受的金鑰長度（bytes）：`min..=max` 中每隔 `step` 一個，產生金鑰時用 `default`。
#[derive(Clone, Copy, Debug)]
#[allow(dead_code, reason = "產生金鑰的 generator 模組會讀")]
pub(in crate::cipher) struct Lengths {
    min: usize,
    max: usize,
    step: usize,
    default: usize,
}

#[allow(
    dead_code,
    reason = "產生金鑰的 generator 模組會用；所有演算法的 feature 都關掉時表是空的"
)]
impl Lengths {
    pub(super) const fn new(min: usize, max: usize, step: usize, default: usize) -> Self {
        Self {
            min,
            max,
            step,
            default,
        }
    }

    pub(super) const fn exact(len: usize) -> Self {
        Self::new(len, len, 1, len)
    }

    pub(in crate::cipher) fn accepts(&self, len: usize) -> bool {
        (self.min..=self.max).contains(&len) && (len - self.min).is_multiple_of(self.step)
    }

    pub(in crate::cipher) const fn default(&self) -> usize {
        self.default
    }
}

/// 演算法一列：引擎、區塊大小、金鑰長度，以及 BC 有 OID 的組合。
pub(super) struct AlgorithmSpec {
    pub(super) algorithm: Algorithm,
    // 第一個是正式名稱，其餘是別名
    pub(super) names: &'static [&'static str],
    pub(super) block_size: usize,
    #[allow(dead_code, reason = "產生金鑰的 generator 模組會讀")]
    pub(super) key: Lengths,
    pub(super) engine: fn() -> AnyEngine,
    pub(super) oids: &'static [(Mode, Padding, &'static [NamedOid])],
}

/// 沒有模式與 padding 的 cipher 一列（stream cipher 與獨立的 AEAD）。
pub(super) struct StandaloneSpec {
    pub(super) algorithm: Algorithm,
    // 第一個是正式名稱，其餘是別名
    pub(super) names: &'static [&'static str],
    #[allow(dead_code, reason = "產生金鑰的 generator 模組會讀")]
    pub(super) key: Lengths,
    pub(super) cipher: fn() -> AnyCipher,
    pub(super) oids: &'static [NamedOid],
}

/// 模式一列：能搭配哪些演算法，以及沒寫 padding 時補不補位。
pub(super) struct ModeSpec {
    pub(super) mode: Mode,
    // 第一個是正式名稱，其餘是別名
    pub(super) names: &'static [&'static str],
    // AEAD 模式只搭 NoPadding
    pub(super) aead: bool,
    // 只接受這些區塊大小；空的表示不限
    pub(super) block_sizes: &'static [usize],
    // 可以處理不滿一個區塊的最後一段（CFB、OFB、CTR）：沒寫 padding 時不補位
    pub(super) partial_block: bool,
}

impl ModeSpec {
    pub(super) const fn is_aead(&self) -> bool {
        self.aead
    }

    pub(super) fn supports(&self, algorithm: &AlgorithmSpec) -> bool {
        self.block_sizes.is_empty() || self.block_sizes.contains(&algorithm.block_size)
    }

    /// 同 BC：沒寫 padding 時，AEAD 與不滿區塊也能處理的模式不補位，其餘補 PKCS7。
    pub(super) const fn default_padding(&self) -> Padding {
        if self.is_aead() || self.partial_block {
            Padding::NoPadding
        } else {
            Padding::Pkcs7
        }
    }
}

/// padding 一列。
pub(super) struct PaddingSpec {
    pub(super) padding: Padding,
    // 第一個是正式名稱，其餘是別名
    pub(super) names: &'static [&'static str],
}
