//! 補齊寬度的 Montgomery 參數，以 `Arc` 共享。

use alloc::sync::Arc;
use core::fmt;

use super::mul::montgomery_inverse;
use super::padded_mul::{double_mod, one_mod};
use crate::{Odd, PaddedBigUint, Word};

/// 一組奇模數的 Montgomery 參數，內部以 [`Arc`] 共享。
///
/// 每個 [`super::PaddedMontyForm`] 都持有一份這個型別。它是 owned 的 —— 不帶
/// 生命週期，所以能存進結構、跨執行緒傳遞；而 clone 只是一次參考計數遞增，
/// 不會複製模數與兩個 radix 常數。深拷貝在這裡不可接受：常數時間的模冪每個
/// 位元都會產生新的 form，深拷貝會變成數千次配置。
///
/// 參數全部由公開的模數導出，本身不是秘密；建構過程不必是常數時間。
#[derive(Clone)]
pub struct PaddedMontyParams(Arc<Inner>);

struct Inner {
    modulus: Odd<PaddedBigUint>,
    mod_neg_inv: Word,
    plain_one: PaddedBigUint,
    one: PaddedBigUint,
    r2: PaddedBigUint,
}

impl PaddedMontyParams {
    /// 由奇模數導出參數。寬度即模數的寬度。
    ///
    /// `R` 與 `R²` 都用逐次倍加取模求出，不需要除法。輸入是公開的，
    /// 所以這裡只求正確，不求最快。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::PaddedMontyParams;
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = Odd::new(PaddedBigUint::from_be_bytes(&[101], 2).unwrap()).unwrap();
    /// let params = PaddedMontyParams::new(modulus);
    /// assert_eq!(params.modulus().len(), 2);
    /// ```
    pub fn new(modulus: Odd<PaddedBigUint>) -> Self {
        let width = modulus.as_ref().len();
        let mod_neg_inv = if width == 0 {
            0
        } else {
            montgomery_inverse(modulus.as_ref().as_limbs()[0].to_word())
        };

        // one = R mod n，由 1 連續倍加 `width * Word::BITS` 次得到。
        let bits = width * Word::BITS as usize;
        let plain_one = one_mod(modulus.as_ref());
        let mut one = plain_one.clone();
        for _ in 0..bits {
            one = double_mod(&one, modulus.as_ref());
        }

        // r2 = R² mod n，從 R mod n 再倍加同樣的次數。
        let mut r2 = one.clone();
        for _ in 0..bits {
            r2 = double_mod(&r2, modulus.as_ref());
        }

        Self(Arc::new(Inner {
            modulus,
            mod_neg_inv,
            plain_one,
            one,
            r2,
        }))
    }

    /// 奇模數。
    pub fn modulus(&self) -> &PaddedBigUint {
        self.0.modulus.as_ref()
    }

    /// 一般表示法的 `1 mod n`，離開 Montgomery 域時當乘數用。
    pub(super) fn plain_one(&self) -> &PaddedBigUint {
        &self.0.plain_one
    }

    /// Montgomery 域中的一，也就是 `R mod n`。
    pub fn one(&self) -> &PaddedBigUint {
        &self.0.one
    }

    /// `R² mod n`，用來把值送進 Montgomery 域。
    pub fn r2(&self) -> &PaddedBigUint {
        &self.0.r2
    }

    /// 模數的寬度，以 limb 計。公開資訊。
    pub fn len(&self) -> usize {
        self.0.modulus.as_ref().len()
    }

    /// 模數寬度是否為零。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `-n⁻¹ mod 2^Word::BITS`。
    pub(super) fn mod_neg_inv(&self) -> Word {
        self.0.mod_neg_inv
    }

    /// 兩組參數是否可以互相運算。
    ///
    /// 先比參考位址，這是同一份 `Arc` 的常見情形；位址不同時才逐 limb 比模數，
    /// 好讓同一組參數被建立兩次也仍然能用。
    pub(super) fn compatible_with(&self, rhs: &Self) -> bool {
        Arc::ptr_eq(&self.0, &rhs.0) || self.modulus() == rhs.modulus()
    }
}

/// 只輸出模數寬度。模數本身是公開的，但保持與 [`super::PaddedMontyForm`] 一致。
impl fmt::Debug for PaddedMontyParams {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("PaddedMontyParams")
            .field("limbs", &self.len())
            .finish_non_exhaustive()
    }
}
