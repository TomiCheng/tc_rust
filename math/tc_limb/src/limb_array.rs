use crate::{Choice, ConditionallySelectable, ConstantTimeEq, Limb};
use core::cmp::Ordering;

mod arithmetic;

/// 恰好 `N` 個小端序 limb，不配置記憶體，欄位私有。
///
/// `N = 0` 代表零寬度的零；加減乘結果仍為零且不溢位。
/// 所有 limb 均為無號儲存，最高位元不是符號位；有號解讀由上層負責。
/// 一般比較、除法、GCD 與其他算術不保證常數時間。
///
/// ```
/// use tc_limb::{Limb, LimbArray};
/// let value = LimbArray::new([Limb::new(7), Limb::new(0)]);
/// assert_eq!(value.as_limbs()[0].to_word(), 7);
/// assert_eq!(LimbArray::<0>::zero().bit_len(), 0);
/// ```
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LimbArray<const N: usize>([Limb; N]);

impl<const N: usize> LimbArray<N> {
    /// 使用恰好 `N` 個小端序 limb 建立數值，保留最高位的零。
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// assert_eq!(LimbArray::new([Limb::new(3)]).as_limbs(), &[Limb::new(3)]);
    /// ```
    pub const fn new(limbs: [Limb; N]) -> Self {
        Self(limbs)
    }

    /// 建立全部 limb 為零的數值。
    /// ```
    /// use tc_limb::LimbArray;
    /// assert!(LimbArray::<4>::zero().is_zero());
    /// ```
    pub const fn zero() -> Self {
        Self([Limb::new(0); N])
    }

    /// 借用全部小端序 limb，保留固定長度。
    /// ```
    /// use tc_limb::LimbArray;
    /// assert_eq!(LimbArray::<3>::zero().as_limbs().len(), 3);
    /// ```
    pub const fn as_limbs(&self) -> &[Limb; N] {
        &self.0
    }

    /// 取出全部小端序 limb。
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// assert_eq!(LimbArray::<2>::zero().into_limbs(), [Limb::new(0); 2]);
    /// ```
    pub const fn into_limbs(self) -> [Limb; N] {
        self.0
    }

    /// 回傳固定寬度的和與最高 limb 的進位旗標。
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// let max = LimbArray::new([Limb::new(Word::MAX)]);
    /// assert_eq!(max.add(&LimbArray::new([Limb::new(1)])), (LimbArray::zero(), true));
    /// ```
    pub fn add(&self, rhs: &Self) -> (Self, bool) {
        let (value, overflow) = Self::add_words(&self.0, &rhs.0);
        (Self(value), overflow)
    }

    /// 回傳固定寬度的差與最低位減法造成的最終借位旗標。
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// let one = LimbArray::new([Limb::new(1)]);
    /// assert_eq!(LimbArray::zero().sub(&one), (LimbArray::new([Limb::new(Word::MAX)]), true));
    /// ```
    pub fn sub(&self, rhs: &Self) -> (Self, bool) {
        let (value, overflow) = Self::sub_words(&self.0, &rhs.0);
        (Self(value), overflow)
    }

    /// 回傳乘積低半部；高半部非零時溢位旗標為真。
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// let max = LimbArray::new([Limb::new(Word::MAX)]);
    /// assert_eq!(max.mul(&max), (LimbArray::new([Limb::new(1)]), true));
    /// ```
    pub fn mul(&self, rhs: &Self) -> (Self, bool) {
        let (value, overflow) = Self::mul_words(&self.0, &rhs.0);
        (Self(value), overflow)
    }

    /// 回傳完整乘積的 `(低半部, 高半部)`，各有 `N` 個 limb。
    ///
    /// 完整值為 `low + high * 2^(N * Word::BITS)`。
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// let max = LimbArray::new([Limb::new(Word::MAX)]);
    /// assert_eq!(max.mul_wide(&max), (LimbArray::new([Limb::new(1)]),
    ///                                LimbArray::new([Limb::new(Word::MAX - 1)])));
    /// ```
    pub fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        let (low, high) = Self::mul_wide_words(&self.0, &rhs.0);
        (Self(low), Self(high))
    }

    /// 回傳完整平方的低半部與高半部。
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// let x = LimbArray::new([Limb::new(7)]);
    /// assert_eq!(x.square_wide(), (LimbArray::new([Limb::new(49)]), LimbArray::zero()));
    /// ```
    pub fn square_wide(&self) -> (Self, Self) {
        let (low, high) = Self::square_wide_words(&self.0);
        (Self(low), Self(high))
    }

    /// 將完整乘積加到雙倍寬度累加器，回傳超過 `2N` 個 limb 的溢位旗標。
    ///
    /// `low` 與 `high` 原地更新，溢位時保留模 `2^(2N * Word::BITS)` 的結果。
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// let x = LimbArray::new([Limb::new(3)]);
    /// let mut low = LimbArray::new([Limb::new(1)]);
    /// let mut high = LimbArray::zero();
    /// assert!(!x.mul_add_to(&x, &mut low, &mut high));
    /// assert_eq!(low.as_limbs()[0].to_word(), 10);
    /// ```
    pub fn mul_add_to(&self, rhs: &Self, low: &mut Self, high: &mut Self) -> bool {
        Self::mul_add_to_words(&self.0, &rhs.0, &mut low.0, &mut high.0)
    }

    /// 無號除法，回傳商與餘數；控制流程依數值改變。
    ///
    /// # Panics
    /// 除數為零時 panic，包含 `N = 0`。
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// let a = LimbArray::new([Limb::new(17)]);
    /// let b = LimbArray::new([Limb::new(5)]);
    /// assert_eq!(a.div_rem(&b), (LimbArray::new([Limb::new(3)]), LimbArray::new([Limb::new(2)])));
    /// ```
    pub fn div_rem(&self, rhs: &Self) -> (Self, Self) {
        let (quotient, remainder) = Self::div_rem_words(&self.0, &rhs.0);
        (Self(quotient), Self(remainder))
    }

    /// 對雙倍寬度無號數取餘數，`self` 是低半部，`high` 是高半部。
    ///
    /// # Panics
    /// `modulus` 為零時 panic，包含 `N = 0`。此方法不保證常數時間。
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// let low = LimbArray::new([Limb::new(Word::MAX)]);
    /// let high = LimbArray::new([Limb::new(1)]);
    /// let modulus = LimbArray::new([Limb::new(2)]);
    /// assert_eq!(low.wide_rem(&high, &modulus), LimbArray::new([Limb::new(1)]));
    /// ```
    pub fn wide_rem(&self, high: &Self, modulus: &Self) -> Self {
        Self(Self::wide_rem_words(&self.0, &high.0, &modulus.0))
    }

    /// 回傳模 `2^(N * Word::BITS)` 的加法反元素；零寬度仍回傳零。
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// assert_eq!(LimbArray::new([Limb::new(1)]).wrapping_neg(), LimbArray::new([Limb::new(Word::MAX)]));
    /// ```
    pub fn wrapping_neg(&self) -> Self {
        Self(Self::wrapping_neg_words(&self.0))
    }

    /// 無號最大公因數，`gcd(0, 0) = 0`；控制流程依數值改變。
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// assert_eq!(LimbArray::new([Limb::new(12)]).gcd(&LimbArray::new([Limb::new(8)])),
    ///            LimbArray::new([Limb::new(4)]));
    /// ```
    pub fn gcd(&self, rhs: &Self) -> Self {
        Self(Self::gcd_words(&self.0, &rhs.0))
    }

    /// 無號表示需要的有效位元數；零回傳零。
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// assert_eq!(LimbArray::new([Limb::new(8)]).bit_len(), 4);
    /// ```
    pub fn bit_len(&self) -> usize {
        Self::bit_len_words(&self.0)
    }

    /// 讀取位元，索引零是最低位元。
    ///
    /// # Panics
    /// 索引超出固定寬度時 panic；零寬度沒有有效索引。
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// let x = LimbArray::new([Limb::new(8)]);
    /// assert!(x.test_bit(3));
    /// assert!(!x.test_bit(0));
    /// ```
    pub fn test_bit(&self, index: usize) -> bool {
        Self::test_bit_words(&self.0, index)
    }

    /// 是否所有 limb 都為零；零寬度回傳真。此比較可能提早退出。
    /// ```
    /// use tc_limb::LimbArray;
    /// assert!(LimbArray::<0>::zero().is_zero());
    /// ```
    pub fn is_zero(&self) -> bool {
        Self::is_zero_words(&self.0)
    }

    /// 是否等於一；零寬度回傳假。此比較可能提早退出。
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// assert!(LimbArray::new([Limb::new(1), Limb::new(0)]).is_one());
    /// ```
    pub fn is_one(&self) -> bool {
        Self::is_one_words(&self.0)
    }

    /// 原地邏輯右移一位，捨棄最低位元；零寬度不變。
    /// ```
    /// use tc_limb::{Limb, LimbArray};
    /// let mut x = LimbArray::new([Limb::new(7)]);
    /// x.shr_one();
    /// assert_eq!(x.as_limbs()[0].to_word(), 3);
    /// ```
    pub fn shr_one(&mut self) {
        Self::shr_one_words(&mut self.0);
    }

    /// 原地左移一位並回傳被移出的最高位元；零寬度回傳假。
    /// ```
    /// use tc_limb::{Limb, LimbArray, Word};
    /// let mut x = LimbArray::new([Limb::new(1 << (Word::BITS - 1))]);
    /// assert!(x.shl_one());
    /// assert!(x.is_zero());
    /// ```
    pub fn shl_one(&mut self) -> bool {
        Self::shl_one_words(&mut self.0)
    }
}

impl<const N: usize> Default for LimbArray<N> {
    fn default() -> Self {
        Self::zero()
    }
}

/// 從最高 limb 開始作無號數值比較，可能提早退出。
/// ```
/// use tc_limb::{Limb, LimbArray};
/// use core::cmp::Ordering;
/// let a = LimbArray::new([Limb::new(9), Limb::new(0)]);
/// let b = LimbArray::new([Limb::new(0), Limb::new(1)]);
/// assert_eq!(a.cmp(&b), Ordering::Less);
/// ```
impl<const N: usize> Ord for LimbArray<N> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        Self::cmp_words(&self.0, &rhs.0)
    }
}
impl<const N: usize> PartialOrd for LimbArray<N> {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

/// 逐 limb 選取且不依輸入值分支，零選 `a`，一選 `b`。
/// ```
/// use tc_limb::{Choice, ConditionallySelectable, Limb, LimbArray};
/// let a = LimbArray::<1>::zero();
/// let b = LimbArray::new([Limb::new(7)]);
/// assert_eq!(LimbArray::conditional_select(&a, &b, Choice::from_lsb(1)), b);
/// ```
impl<const N: usize> ConditionallySelectable for LimbArray<N> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<[Limb; N]>::conditional_select(&a.0, &b.0, choice))
    }
}

/// 比較全部 `N` 個 limb，不提早退出；零寬度的兩個值相等。
/// ```
/// use tc_limb::{ConstantTimeEq, LimbArray};
/// assert_eq!(LimbArray::<0>::zero().ct_eq(&LimbArray::zero()).unwrap_u8(), 1);
/// ```
impl<const N: usize> ConstantTimeEq for LimbArray<N> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.0.ct_eq(&rhs.0)
    }
}
