//! 補齊寬度的模冪：秘密指數走固定排程，公開指數走滑動視窗。

use alloc::vec::Vec;

use super::exponentiation_window;
use super::padded_form::PaddedMontyForm;
use super::padded_mul::montgomery_mul_into;
use crate::{PaddedBigUint, Word};

impl PaddedMontyForm {
    /// CT：對秘密指數做模冪，走「平方後永遠乘一次」。
    ///
    /// 圈數是 `exponent.len() * Word::BITS`，連前導零的位元也照走，
    /// 所以不洩漏指數的最高位位置。每一位元都做一次平方與一次乘法，
    /// 再用無分支的選擇丟掉不要的那個。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = Odd::new(PaddedBigUint::from_be_bytes(&[101], 1).unwrap()).unwrap();
    /// let params = PaddedMontyParams::new(modulus);
    /// let base = PaddedMontyForm::new_ct(&PaddedBigUint::from_be_bytes(&[7], 1).unwrap(), params);
    /// let exponent = PaddedBigUint::from_be_bytes(&[3], 1).unwrap();
    /// // 7^3 = 343 = 3 * 101 + 40
    /// assert_eq!(
    ///     base.pow_ct(&exponent).retrieve(),
    ///     PaddedBigUint::from_be_bytes(&[40], 1).unwrap()
    /// );
    /// ```
    pub fn pow_ct(&self, exponent: &PaddedBigUint) -> Self {
        let params = self.params().clone();
        let modulus = params.modulus();
        let inverse = params.mod_neg_inv();
        let base = self.as_value();

        // 三個緩衝在迴圈外配置一次，之後靠 swap 換手，內圈完全不配置。
        let mut result = params.one().clone();
        let mut squared = PaddedBigUint::zero_with_limbs(params.len());
        let mut multiplied = PaddedBigUint::zero_with_limbs(params.len());

        for bit in (0..exponent.len() * Word::BITS as usize).rev() {
            montgomery_mul_into(&mut squared, &result, &result, modulus, inverse);
            montgomery_mul_into(&mut multiplied, &squared, base, modulus, inverse);
            // 無分支選擇，再把選中的那個換成下一輪的 result。
            squared.conditional_assign(&multiplied, exponent.bit_choice(bit));
            core::mem::swap(&mut result, &mut squared);
        }

        Self::from_value(result, params)
    }

    /// 變動時間：**只能用於公開指數**。走滑動視窗的模冪。
    ///
    /// 圈數、分支與查表位置都由指數決定，用在私鑰指數上會洩漏它。
    /// 這個版本是給公開指數用的 —— 例如 RSA 的驗算與盲化都是拿公開的 `e` 做冪。
    pub fn pow(&self, exponent: &PaddedBigUint) -> Self {
        let bits = exponent.bit_len();
        let mut result = Self::one(self.params().clone());
        if bits == 0 {
            return result;
        }

        let window = exponentiation_window(bits);
        let table_len = 1_usize << (window - 1);
        let mut odd_powers = Vec::with_capacity(table_len);
        odd_powers.push(self.clone());
        if table_len > 1 {
            let squared = self.square();
            for index in 1..table_len {
                odd_powers.push(&odd_powers[index - 1] * &squared);
            }
        }

        let mut remaining = bits;
        while remaining != 0 {
            let high = remaining - 1;
            if !exponent.test_bit(high) {
                result = result.square();
                remaining -= 1;
                continue;
            }

            let mut low = remaining.saturating_sub(window);
            while !exponent.test_bit(low) {
                low += 1;
            }
            let mut window_value = 0_usize;
            for bit in (low..=high).rev() {
                window_value = (window_value << 1) | usize::from(exponent.test_bit(bit));
            }
            for _ in low..=high {
                result = result.square();
            }
            result = &result * &odd_powers[window_value >> 1];
            remaining = low;
        }

        result
    }
}
