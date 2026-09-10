//! 巢狀深度的預算。
//!
//! ASN.1 的 constructed 型別可以無限往下巢狀，而解碼是遞迴的 —— 沒有上限的話
//! 一段刻意構造的輸入就能耗盡堆疊。這個型別把「還能再深幾層」帶在解碼路徑上。
//!
//! 它同時也保護解構：`Vec<Asn1Object>` 的 `Drop` 一樣是遞迴的，深樹在釋放時
//! 會爆堆疊。解碼時擋住了，就不會有那麼深的樹存在。

use crate::asn1_error::Asn1Error;

/// 還能往下走幾層。
///
/// 每個 [`TryDecode::try_decode`] 在進入時消耗一層，constructed 型別把剩下的
/// 傳給子元素。
///
/// [`TryDecode::try_decode`]: crate::TryDecode::try_decode
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Depth(u32);

impl Depth {
    /// 預設上限。
    ///
    /// 32 遠高於真實憑證用到的深度（十來層），也遠低於會出事的堆疊用量。
    pub const DEFAULT: Self = Self(32);

    /// 自訂上限。
    pub const fn new(limit: u32) -> Self {
        Self(limit)
    }

    /// 剩餘的層數。
    pub const fn get(self) -> u32 {
        self.0
    }

    /// 常數時間：消耗一層，回傳剩下的預算。
    ///
    /// 預算用完時回 [`Asn1Error::DepthExceeded`]。檢查與扣減是同一個動作，
    /// 呼叫端沒辦法只做一半。
    pub const fn descend(self) -> Result<Self, Asn1Error> {
        match self.0.checked_sub(1) {
            Some(remaining) => Ok(Self(remaining)),
            None => Err(Asn1Error::DepthExceeded),
        }
    }
}

impl Default for Depth {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descending_spends_one_level_at_a_time() {
        let depth = Depth::new(2);
        let depth = depth.descend().unwrap();
        assert_eq!(depth.get(), 1);

        let depth = depth.descend().unwrap();
        assert_eq!(depth.get(), 0);
    }

    #[test]
    fn descending_past_the_budget_is_rejected() {
        assert_eq!(Depth::new(0).descend(), Err(Asn1Error::DepthExceeded));
    }

    #[test]
    fn the_default_budget_is_deeper_than_any_real_certificate() {
        assert!(Depth::DEFAULT.get() >= 16);
    }
}
