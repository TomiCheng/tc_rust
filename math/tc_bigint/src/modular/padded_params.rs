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
/// 不會複製模數與 radix 常數；多個 form 因此能共用同一組預計算結果。
///
/// 變動時間：參數建構只能用於公開值。參數全部由公開的模數導出，本身不是秘密；
/// 秘密輸入進域請用 [`super::PaddedMontyForm::new_ct`]。
///
/// # Examples
///
/// ```
/// use tc_bigint::modular::PaddedMontyParams;
/// use tc_bigint::{Odd, PaddedBigUint};
///
/// let modulus = Odd::new(PaddedBigUint::from_be_bytes(&[101], 2).unwrap()).unwrap();
/// let params = PaddedMontyParams::new(modulus);
/// let shared = params.clone();
/// // clone 共用同一份模數，而不是建立內容相等的新配置。
/// assert!(core::ptr::eq(params.modulus(), shared.modulus()));
/// ```
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
    /// 變動時間：只能用於公開值。由奇模數導出參數，寬度即模數寬度。
    ///
    /// `R` 與 `R²` 都用逐次倍加取模求出，不需要除法。輸入是公開的，
    /// 所以這裡只求正確，不求最快。秘密輸入進域請用 [`super::PaddedMontyForm::new_ct`]。
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

    /// CT：借出公開的奇模數，不掃描數值。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::PaddedMontyParams;
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = PaddedBigUint::from_be_bytes(&[101], 2).unwrap();
    /// let params = PaddedMontyParams::new(Odd::new(modulus.clone()).unwrap());
    /// assert_eq!(params.modulus(), &modulus);
    /// assert_eq!(params.modulus().len(), 2);
    /// ```
    pub fn modulus(&self) -> &PaddedBigUint {
        self.0.modulus.as_ref()
    }

    /// 一般表示法的 `1 mod n`，離開 Montgomery 域時當乘數用。
    pub(super) fn plain_one(&self) -> &PaddedBigUint {
        &self.0.plain_one
    }

    /// CT：借出 Montgomery 域中的一，也就是 `R mod n`。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::PaddedMontyParams;
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = PaddedBigUint::from_be_bytes(&[101], 2).unwrap();
    /// let params = PaddedMontyParams::new(Odd::new(modulus.clone()).unwrap());
    /// // 這是 R mod n，不是一般表示法的整數一。
    /// use tc_bigint::{ArrayEncoding, BigUint};
    /// let storage_bits = modulus.to_be_bytes().len() * 8;
    /// let radix = BigUint::from(1_u8) << storage_bits;
    /// assert_eq!(params.one().to_big_uint(), &radix % modulus.to_big_uint());
    /// ```
    pub fn one(&self) -> &PaddedBigUint {
        &self.0.one
    }

    /// CT：借出 `R² mod n`，用來把值送進 Montgomery 域。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::PaddedMontyParams;
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = PaddedBigUint::from_be_bytes(&[101], 2).unwrap();
    /// let params = PaddedMontyParams::new(Odd::new(modulus.clone()).unwrap());
    /// use tc_bigint::{ArrayEncoding, BigUint};
    /// let storage_bits = modulus.to_be_bytes().len() * 8;
    /// let radix = BigUint::from(1_u8) << storage_bits;
    /// assert_eq!(params.r2().to_big_uint(), (&radix * &radix) % modulus.to_big_uint());
    /// ```
    pub fn r2(&self) -> &PaddedBigUint {
        &self.0.r2
    }

    /// CT：模數的寬度，以 limb 計。公開資訊。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::PaddedMontyParams;
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = PaddedBigUint::from_be_bytes(&[101], 2).unwrap();
    /// let params = PaddedMontyParams::new(Odd::new(modulus.clone()).unwrap());
    /// assert_eq!(params.len(), 2);
    /// assert_eq!(params.one().len(), params.len());
    /// ```
    pub fn len(&self) -> usize {
        self.0.modulus.as_ref().len()
    }

    /// CT：模數寬度是否為零。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::PaddedMontyParams;
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = PaddedBigUint::from_be_bytes(&[101], 2).unwrap();
    /// let params = PaddedMontyParams::new(Odd::new(modulus.clone()).unwrap());
    /// // 奇模數不可能是零，因此有效參數至少有一個 limb。
    /// assert!(!params.is_empty());
    /// ```
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
