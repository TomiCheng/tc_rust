use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Rem, Shl, Shr, Sub};
use core::str::FromStr;

use rand_core::Rng;

// no_std 下沒有 std prelude，需從 alloc 顯式引入這些型別／巨集；
// std build 由 prelude 提供，故僅在關閉 std 時引入，避免重複 import 警告。
#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec,
    vec::Vec,
};

// 質數相關運算（Miller-Rabin、隨機質數生成）拆到子模組，隔離 `rand` 相依，
// 讓本檔維持純算術。子模組是本模組的子孫，看得到 sign/magnitude 等私有項目。
mod prime;

// 位元組序列化（be/le × signed/unsigned × from/to/into）同樣拆到子模組縮短本檔；
// 仍靠父模組的 make_magnitude_* / byte_length* / BufferTooSmall（子孫可見）。
mod bytes;

// u32 詞序列化：bytes 家族的 u32 版（同 be/le × signed/unsigned × from/to/into）。
// 自帶 helper（magnitude 本就是 u32 詞，無須父模組的位元組 helper）。
mod words;

/// 一個 magnitude 字的位元數（= 32）。集中定義，避免散落的 magic number。
const WORD_BITS: usize = u32::BITS as usize;

/// 滑動視窗指數化的視窗寬度門檻：指數位元長度超過第 i 個門檻，就多用一個
/// extra_bit（視窗更寬）。純整數字面值 → 可 `const`（不像堆積型常數需執行期初始化）。
const EXP_WINDOW_THRESHOLDS: [u32; 8] = [7, 25, 81, 241, 673, 1793, 4609, u32::MAX];

/// Error returned when parsing a [`BigInteger`] from a string fails.
///
/// Describes problems with the input string only; an out-of-range radix is a
/// caller error and panics instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseBigIntegerError {
    /// The input had no digits (empty string, or only a sign).
    Empty,
    /// A character was not a valid digit for the radix (invalid character, or
    /// a digit greater than or equal to the radix).
    InvalidDigit {
        /// Character index (into the original string) of the offending character.
        index: usize,
        /// The offending character.
        ch: char,
    },
}

impl core::fmt::Display for ParseBigIntegerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseBigIntegerError::Empty => f.write_str("cannot parse integer from empty string"),
            ParseBigIntegerError::InvalidDigit { index, ch } => {
                write!(f, "invalid digit '{ch}' at position {index}")
            }
        }
    }
}

impl core::error::Error for ParseBigIntegerError {}

/// Error returned by the `try_to_bytes_*_into` methods when the destination
/// buffer is smaller than the encoding requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall {
    /// Number of bytes the encoding needs.
    pub needed: usize,
    /// Number of bytes the buffer provides.
    pub available: usize,
}

impl core::fmt::Display for BufferTooSmall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "buffer too small: need {} bytes, got {}",
            self.needed, self.available
        )
    }
}

impl core::error::Error for BufferTooSmall {}

/// Error returned when a [`BigInteger`] is out of range for the target integer
/// type in a `TryFrom`/`TryInto` conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TryFromBigIntegerError(());

impl core::fmt::Display for TryFromBigIntegerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("number out of range for the target integer type")
    }
}

impl core::error::Error for TryFromBigIntegerError {}

#[derive(Clone, Debug)]
pub struct BigInteger {
    sign: i32,
    /// 不可變、big-endian、無前導零；不可變型別故用 `Box<[u32]>` 而非 `Vec<u32>`。
    magnitude: Box<[u32]>,
}

impl BigInteger {
    // 施工端用 `Vec<u32>` 傳入，儲存時落地成 `Box<[u32]>`。
    fn new(sign: i32, magnitude: Vec<u32>) -> Self {
        BigInteger { sign, magnitude: magnitude.into_boxed_slice() }
    }

    /// 檢查版建構式（對應 bc-csharp `new BigInteger(sign, mag, checkMag: true)`）：
    /// 去前導零；若全為零則符號歸 0，維持「無前導零 / sign==0 ⟺ magnitude 空」不變量。
    ///
    /// 用於位元運算等「結果 magnitude 可能帶前導零或全零」的場合；`new` 本身不做檢查。
    fn from_checked_magnitude(sign: i32, magnitude: Vec<u32>) -> Self {
        let magnitude = trim_leading_zeros(magnitude);
        let sign = if magnitude.is_empty() { 0 } else { sign };
        BigInteger::new(sign, magnitude)
    }

    /// Returns the sign of this value: `-1` (negative), `0` (zero), or `1` (positive).
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_i32(-5).sign(), -1);
    /// assert_eq!(BigInteger::from_i32(0).sign(), 0);
    /// assert_eq!(BigInteger::from_i32(5).sign(), 1);
    /// ```
    pub fn sign(&self) -> i32 {
        self.sign
    }

    /// Returns `true` if this value is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert!(BigInteger::from_u32(0).is_zero());
    /// assert!(!BigInteger::from_u32(5).is_zero());
    /// ```
    pub fn is_zero(&self) -> bool {
        self.sign == 0
    }

    /// Returns the absolute value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_i32(-5).abs(), BigInteger::from_i32(5));
    /// ```
    pub fn abs(self) -> BigInteger {
        if self.sign >= 0 {
            // 已非負：原封不動
            self
        } else {
            // 負 → 正：搬移 buffer 重用，僅翻正符號
            BigInteger::new(1, Vec::from(self.magnitude))
        }
    }

    /// Returns `self²` (always non-negative).
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_i32(-7).square(), BigInteger::from_i32(49));
    /// ```
    pub fn square(&self) -> BigInteger {
        if self.sign == 0 {
            return BigInteger::from_u32(0);
        }
        // 2^k 的平方 = 2^(2k) = self << k（k = bit_length-1）；is_power_of_two 保證為正
        if self.is_power_of_two() {
            return self << (self.bit_length() - 1);
        }
        // 平方恆正；square_magnitude 已 trim，直接生建構
        BigInteger::new(1, square_magnitude(&self.magnitude))
    }

    /// Returns `self` raised to the non-negative power `exp` (`self^exp`).
    ///
    /// `x.pow(0)` is `1` for every `x`, including `0`. This is ordinary,
    /// non-modular exponentiation via square-and-multiply; for the modular
    /// form see [`BigInteger::mod_pow`].
    ///
    /// # Panics
    ///
    /// Panics only if the result would exceed `u32::MAX` bits — an
    /// astronomically large value that realistic inputs never reach.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_i32(3).pow(4), BigInteger::from_i32(81));
    /// assert_eq!(BigInteger::from_i32(-2).pow(3), BigInteger::from_i32(-8));
    /// assert_eq!(BigInteger::from_i32(7).pow(0), BigInteger::from_i32(1));
    /// ```
    pub fn pow(&self, exp: u32) -> BigInteger {
        if exp == 0 {
            return BigInteger::from_u32(1); // x^0 = 1（含 0^0 = 1，依慣例）
        }
        if self.sign == 0 {
            return BigInteger::from_u32(0); // 0^exp = 0（此時 exp > 0）
        }
        // 正的 2^k：(2^k)^exp = 2^(k·exp)，一次位移取代整串乘法
        // （is_power_of_two 要求 sign > 0，故不會把負底的符號算錯）
        if self.is_power_of_two() {
            let bits = (self.bit_length() - 1) as u64 * exp as u64;
            let shift = u32::try_from(bits).expect("pow: result exceeds u32::MAX bits");
            return &BigInteger::from_u32(1) << shift;
        }
        // 逐位平方相乘：從最低位掃 exp，遇 1 就把當前的 z（= self^(2^i)）乘進 y
        let mut exp = exp;
        let mut y = BigInteger::from_u32(1);
        let mut z = self.clone();
        loop {
            if exp & 1 == 1 {
                y = &y * &z;
            }
            exp >>= 1;
            if exp == 0 {
                break;
            }
            z = z.square();
        }
        y
    }

    /// Returns the truncated quotient and remainder `(self / divisor, self % divisor)`.
    ///
    /// Division truncates toward zero: the quotient's sign is the product of the
    /// operand signs, and the remainder takes the dividend's sign.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let (q, r) = BigInteger::from_i32(-7).div_rem(&BigInteger::from_i32(2));
    /// assert_eq!(q, BigInteger::from_i32(-3)); // 截斷向零
    /// assert_eq!(r, BigInteger::from_i32(-1)); // 餘數跟被除數同號
    /// ```
    pub fn div_rem(&self, divisor: &BigInteger) -> (BigInteger, BigInteger) {
        if divisor.sign == 0 {
            panic!("attempt to divide by zero");
        }
        if self.sign == 0 {
            return (BigInteger::from_u32(0), BigInteger::from_u32(0)); // 0 / y = (0, 0)
        }
        let (q_mag, r_mag) = div_magnitudes(&self.magnitude, &divisor.magnitude);
        // 截斷向零：商號 = 兩號相乘；餘號 = 被除數號。空 magnitude 由 from_checked 歸 0
        let quotient = BigInteger::from_checked_magnitude(self.sign * divisor.sign, q_mag);
        let remainder = BigInteger::from_checked_magnitude(self.sign, r_mag);
        (quotient, remainder)
    }

    /// Returns the least non-negative remainder of `self` divided by `other`
    /// (Euclidean modulo). The result is always in `[0, |other|)`.
    ///
    /// Unlike `%` (which takes the dividend's sign), this is always non-negative.
    /// Works for any non-zero `other`, including negative.
    ///
    /// # Panics
    ///
    /// Panics if `other` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_i32(-7).rem_euclid(&BigInteger::from_i32(3)), BigInteger::from_i32(2));
    /// assert_eq!(BigInteger::from_i32(-7).rem_euclid(&BigInteger::from_i32(-3)), BigInteger::from_i32(2));
    /// ```
    pub fn rem_euclid(&self, other: &BigInteger) -> BigInteger {
        if other.sign == 0 {
            panic!("attempt to calculate the remainder with a divisor of zero");
        }
        let r = self % other; // 截斷餘數：符號同 self，落在 (-|other|, |other|)
        if r.sign < 0 {
            // 補上 |other| 使結果非負：other 正就加、負就減
            if other.sign > 0 { &r + other } else { &r - other }
        } else {
            r
        }
    }

    /// Returns the greatest common divisor of `self` and `other`, always
    /// non-negative. Signs are ignored (works on absolute values).
    ///
    /// `gcd(0, 0)` is `0`; `gcd(a, 0)` is `|a|`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_i32(-12).gcd(&BigInteger::from_i32(18)), BigInteger::from_i32(6));
    /// ```
    pub fn gcd(&self, other: &BigInteger) -> BigInteger {
        // 取絕對值輾轉相除：a, b 非負，餘數也非負；b 歸零時 a 即 gcd
        let mut a = self.clone().abs();
        let mut b = other.clone().abs();
        while b.sign != 0 {
            let r = &a % &b;
            a = b;
            b = r;
        }
        a
    }

    /// Returns the modular multiplicative inverse of `self` modulo `modulus`:
    /// the value `x` in `[0, modulus)` with `self * x ≡ 1 (mod modulus)`, or
    /// `None` if `self` and `modulus` are not coprime.
    ///
    /// # Panics
    ///
    /// Panics if `modulus` is not positive.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// // 3⁻¹ ≡ 5 (mod 7)，因為 3·5 = 15 ≡ 1
    /// assert_eq!(
    ///     BigInteger::from_i32(3).mod_inverse(&BigInteger::from_i32(7)),
    ///     Some(BigInteger::from_i32(5))
    /// );
    /// // 4 與 6 不互質 → 無反元素
    /// assert_eq!(BigInteger::from_i32(4).mod_inverse(&BigInteger::from_i32(6)), None);
    /// ```
    pub fn mod_inverse(&self, modulus: &BigInteger) -> Option<BigInteger> {
        if modulus.sign <= 0 {
            panic!("modulus must be positive");
        }
        // 先約簡成 [0, modulus)（非負），避開 extended_gcd 對負 a 的邊界
        let d = self.rem_euclid(modulus);
        let (gcd, x) = extended_gcd(&d, modulus);
        if gcd != 1 {
            return None; // 不互質 → 無反元素
        }
        // x 滿足 d·x ≡ 1 (mod modulus)；調進 [0, modulus)
        Some(if x.sign < 0 { &x + modulus } else { x })
    }

    /// Returns `self.pow(e) mod m` (modular exponentiation) via square-and-multiply.
    ///
    /// A negative exponent computes `(self^|e|)^{-1} mod m`.
    ///
    /// # Panics
    ///
    /// Panics if `m` is not positive, or if `e` is negative and `self` has no
    /// inverse modulo `m`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// // 3^4 = 81 ≡ 4 (mod 7)
    /// assert_eq!(
    ///     BigInteger::from_i32(3).mod_pow(&BigInteger::from_i32(4), &BigInteger::from_i32(7)),
    ///     BigInteger::from_i32(4)
    /// );
    /// ```
    pub fn mod_pow(&self, e: &BigInteger, m: &BigInteger) -> BigInteger {
        if m.sign <= 0 {
            panic!("modulus must be positive");
        }
        if *m == 1 {
            return BigInteger::from_u32(0); // 任何數 mod 1 = 0
        }
        if e.sign == 0 {
            return BigInteger::from_u32(1); // a^0 = 1
        }
        if self.sign == 0 {
            return BigInteger::from_u32(0); // 0^e = 0（此時 e > 0）
        }

        // 滑動視窗指數化；奇模數走 Montgomery、偶模數走 Barrett。
        let neg_exp = e.sign < 0;
        let exp = if neg_exp { -e } else { e.clone() };
        let base = self.rem_euclid(m); // base ∈ [0, m)

        // 奇模數用 Montgomery（RSA 主力，最快）；偶模數 R = 2^k 不可逆，退回 Barrett
        let result = if m.magnitude[m.magnitude.len() - 1] & 1 == 1 {
            BigInteger::mod_pow_monty(&base, &exp, m, true)
        } else {
            BigInteger::mod_pow_barrett(&base, &exp, m)
        };

        if neg_exp {
            // a^(-e) mod m = (a^e mod m)⁻¹；base 與 m 不互質時無解
            result
                .mod_inverse(m)
                .expect("mod_pow: base not invertible modulo m for negative exponent")
        } else {
            result
        }
    }

    /// Drops the lowest `w` magnitude words: `⌊self / (2^32)^w⌋` (truncated
    /// toward zero, sign preserved). A Barrett-reduction building block.
    ///
    /// Keeps the high words, whose leading word is non-zero by the
    /// no-leading-zeros invariant, so no trimming is actually needed here.
    fn divide_words(&self, w: usize) -> BigInteger {
        let n = self.magnitude.len();
        if w >= n {
            return BigInteger::from_u32(0); // 砍光（含超量）→ 0
        }
        // 砍掉低位 w 個字，留高位；最高位字非零，故無前導零可修
        let mag = self.magnitude[..n - w].to_vec();
        BigInteger::from_checked_magnitude(self.sign, mag)
    }

    /// Keeps the lowest `w` magnitude words: `self mod (2^32)^w` (sign
    /// preserved). A Barrett-reduction building block.
    ///
    /// Unlike [`BigInteger::divide_words`], the kept high word can be zero (or
    /// the whole window all-zero), so `from_checked_magnitude` trims / zeroes
    /// it to keep the no-leading-zeros invariant.
    fn remainder_words(&self, w: usize) -> BigInteger {
        let n = self.magnitude.len();
        if w >= n {
            return self.clone(); // 要的比現有多 → 整個 self（已正規化）
        }
        // 留低位 w 個字；高端可能有零字或全零 → 修剪 / 歸零
        let mag = self.magnitude[n - w..].to_vec();
        BigInteger::from_checked_magnitude(self.sign, mag)
    }

    /// Barrett reduction: computes `x mod m` using precomputed constants,
    /// replacing the long division in `%` with word-shifts and multiplies.
    ///
    /// `mr = 2^(32·(k+1))` and `yu = ⌊2^(64·k) / m⌋` (a scaled reciprocal of
    /// `m`), where `k = m.magnitude.len()`. Both are computed once by the
    /// caller and reused across the many reductions of a `mod_pow`.
    ///
    /// Intended for `0 <= x < m²` (the `mod_pow` case), but also handles a
    /// negative `x` via the `mr` correction.
    fn reduce_barrett(x: &BigInteger, m: &BigInteger, mr: &BigInteger, yu: &BigInteger) -> BigInteger {
        let x_len = x.bit_length();
        let m_len = m.bit_length();
        if x_len < m_len {
            return x.clone(); // x < m，已是餘數
        }

        let mut x1 = x.clone();

        // x 只比 m 大一點點（差 <= 1 個位元）時，估計反而繞遠路，直接靠底下的減法修正
        if x_len - m_len > 1 {
            let k = m.magnitude.len();
            debug_assert!(k >= 1);

            // q3 ≈ ⌊x / m⌋：只用「砍字組 + 乘預算倒數 yu」估出商，避開長除法
            let q1 = x.divide_words(k - 1);
            let q2 = &q1 * yu;
            let q3 = q2.divide_words(k + 1);

            // x1 = (x mod b^(k+1)) − (q3·m mod b^(k+1))；差就是餘數（可能還差幾個 m）
            let r1 = x.remainder_words(k + 1);
            let r2 = &q3 * m;
            let r3 = r2.remainder_words(k + 1);

            x1 = &r1 - &r3;
            if x1.sign < 0 {
                // r1 < r3 → 差為負，補回 b^(k+1) = mr（HAC 14.42；判斷 x1 而非輸入 x）
                x1 = &x1 + mr;
            }
        }

        // Barrett 估計最多差 1~2 個 m，減幾次修正到 [0, m)
        while &x1 >= m {
            x1 = &x1 - m;
        }

        x1
    }

    /// Computes `b^e mod m` by sliding-window exponentiation with Barrett
    /// reduction. Requires `0 <= b < m`, `e >= 1`, and `m > 1`.
    ///
    /// Precomputes the Barrett constants once and a table of odd powers
    /// `b^1, b^3, …`, then walks the exponent window-by-window (from
    /// [`get_window_list`]): each window does `bits` squarings plus one
    /// multiply by the matching odd power.
    fn mod_pow_barrett(b: &BigInteger, e: &BigInteger, m: &BigInteger) -> BigInteger {
        let k = m.magnitude.len();
        let mr = &BigInteger::from_u32(1) << (32 * (k as u32 + 1)); // 2^(32(k+1))
        let yu = &(&BigInteger::from_u32(1) << (64 * k as u32)) / m; // ⌊2^(64k) / m⌋

        // 依指數長度選視窗寬度：越長越值得用更寬的視窗
        let mut extra_bits = 0;
        let exp_length = e.bit_length();
        while exp_length > EXP_WINDOW_THRESHOLDS[extra_bits] {
            extra_bits += 1;
        }

        // 奇次方預算表：odd_powers[i] = b^(2i+1)（b¹, b³, b⁵, …）
        let num_powers = 1usize << extra_bits;
        let mut odd_powers = vec![BigInteger::from_u32(0); num_powers];
        odd_powers[0] = b.clone();
        let b2 = BigInteger::reduce_barrett(&b.square(), m, &mr, &yu);
        for i in 1..num_powers {
            odd_powers[i] = BigInteger::reduce_barrett(&(&odd_powers[i - 1] * &b2), m, &mr, &yu);
        }

        let window_list = get_window_list(&e.magnitude, extra_bits);
        debug_assert!(window_list.len() > 1);

        let mut window = window_list[0];
        let mut mul_t = window & 0xFF;
        let mut last_zeros = window >> 8;

        // 第一個視窗：mul_t==1 時可用 b² 起頭省一步，但僅在 last_zeros>=1 才成立
        // （last_zeros==0 時 -=1 會下溢，改走 odd_powers[0] = b）
        let mut y: BigInteger;
        if mul_t == 1 && last_zeros >= 1 {
            y = b2.clone();
            last_zeros -= 1;
        } else {
            y = odd_powers[(mul_t >> 1) as usize].clone();
        }

        let mut window_pos = 1;
        while {
            window = window_list[window_pos];
            window_pos += 1;
            window
        } != u32::MAX
        {
            mul_t = window & 0xFF;
            // 補上一個視窗尾端的零平方，再加上這個視窗 mul_t 的位元數
            let bits = last_zeros + bit_len(mul_t);
            for _ in 0..bits {
                y = BigInteger::reduce_barrett(&y.square(), m, &mr, &yu);
            }
            y = BigInteger::reduce_barrett(&(&y * &odd_powers[(mul_t >> 1) as usize]), m, &mr, &yu);
            last_zeros = window >> 8;
        }

        // 最後一個視窗尾端剩餘的零平方
        for _ in 0..last_zeros {
            y = BigInteger::reduce_barrett(&y.square(), m, &mr, &yu);
        }
        y
    }

    /// Montgomery constant `m' = (-m mod 2^32)^{-1} mod 2^32`, derived from the
    /// low word of `m` (which must be odd). Precomputed once for Montgomery
    /// reduction so the low words cancel without dividing by `m`.
    fn m_prime(&self) -> u32 {
        debug_assert!(self.sign > 0);
        let m_low = self.magnitude[self.magnitude.len() - 1]; // big-endian → 尾端為低字
        let d = 0u32.wrapping_sub(m_low); // -m_low mod 2^32
        debug_assert!(d & 1 == 1); // m 奇 → 低字奇 → d 奇（才有反元素）
        inverse_u32(d)
    }

    /// Computes `b^e` mod `m` by sliding-window exponentiation in the Montgomery
    /// domain. Requires `e >= 1` and `m` **odd** and `> 1`.
    ///
    /// `convert` controls the domain conversions:
    /// - `true`: `b` is an ordinary residue (`0 <= b < m`); it is converted in
    ///   (`b·R mod m`) and the result converted back out — returns `b^e mod m`.
    /// - `false`: `b` is already in Montgomery form; no conversion is done —
    ///   returns `b^e · R mod m` (still in the Montgomery domain). Used by the
    ///   Miller-Rabin test to compare against `R`/`-R` without converting.
    fn mod_pow_monty(b: &BigInteger, e: &BigInteger, m: &BigInteger, convert: bool) -> BigInteger {
        let n = m.magnitude.len();
        let pow_r = 32 * n;
        // m 有 ≥2 位頂端餘裕時，可省略每步的條件減（值仍安放於 n 字內）
        let small_monty_modulus = (m.bit_length() as usize) + 2 <= pow_r;
        let m_prime = m.m_prime();
        let mut y_acc_m = vec![0u32; n + 1]; // Montgomery 乘法的暫存累加器

        // convert=true：把 b 轉進 Montgomery 域（b·R mod m）；false：b 已在域內，直接用
        let mut z_val = if convert {
            (&(b << (pow_r as u32)) % m).magnitude.to_vec()
        } else {
            b.magnitude.to_vec()
        };
        debug_assert!(z_val.len() <= n);
        if z_val.len() < n {
            let mut tmp = vec![0u32; n];
            tmp[(n - z_val.len())..].copy_from_slice(&z_val);
            z_val = tmp;
        }

        // 視窗寬度；小 RSA 指數（單字、設定位 ≤2，如 3 / 65537）維持 extra_bits=0
        let mut extra_bits = 0;
        if e.magnitude.len() > 1 || e.bit_count() > 2 {
            let exp_length = e.bit_length();
            while exp_length > EXP_WINDOW_THRESHOLDS[extra_bits] {
                extra_bits += 1;
            }
        }

        // 奇次方表（Montgomery 域）：odd_powers[i] = z^(2i+1)
        let num_powers = 1usize << extra_bits;
        let mut odd_powers = vec![Vec::new(); num_powers];
        odd_powers[0] = z_val.clone();

        let mut z_squared = z_val.clone();
        square_monty(&mut y_acc_m, &mut z_squared, &m.magnitude, m_prime, small_monty_modulus);

        for i in 1..num_powers {
            odd_powers[i] = odd_powers[i - 1].clone();
            multiply_monty(&mut y_acc_m, &mut odd_powers[i], &z_squared, &m.magnitude, m_prime, small_monty_modulus);
        }

        let window_list = get_window_list(&e.magnitude, extra_bits);
        debug_assert!(window_list.len() > 1);

        let mut window = window_list[0];
        let mut mul_t = window & 0xFF;
        let mut last_zeros = window >> 8;

        // 同 mod_pow_barrett 的守衛：last_zeros==0 時不走 z² 捷徑，避免下溢
        let mut y_val: Vec<u32>;
        if mul_t == 1 && last_zeros >= 1 {
            y_val = z_squared;
            last_zeros -= 1;
        } else {
            y_val = odd_powers[(mul_t >> 1) as usize].clone();
        }

        let mut window_pos = 1;
        while {
            window = window_list[window_pos];
            window_pos += 1;
            window
        } != u32::MAX
        {
            mul_t = window & 0xFF;
            let bits = last_zeros + bit_len(mul_t);
            for _ in 0..bits {
                square_monty(&mut y_acc_m, &mut y_val, &m.magnitude, m_prime, small_monty_modulus);
            }
            multiply_monty(&mut y_acc_m, &mut y_val, &odd_powers[(mul_t >> 1) as usize], &m.magnitude, m_prime, small_monty_modulus);
            last_zeros = window >> 8;
        }

        for _ in 0..last_zeros {
            square_monty(&mut y_acc_m, &mut y_val, &m.magnitude, m_prime, small_monty_modulus);
        }

        if convert {
            // 轉回普通形式：y·R⁻¹ mod m（montgomery_reduce 內含最終條件減）
            montgomery_reduce(&mut y_val, &m.magnitude, m_prime);
        } else if small_monty_modulus && compare_to(&y_val, &m.magnitude).is_ge() {
            // 留在域內，但 small 模式下省略了條件減 → 這裡補一次拉回 [0, m)
            sub_in_place(&mut y_val, &m.magnitude);
        }
        BigInteger::from_checked_magnitude(1, y_val)
    }

    /// Squares a Montgomery-form value once: `b² · R⁻¹ mod m` (stays in the
    /// Montgomery domain). Requires `m` odd and `> 1`. Companion to
    /// [`BigInteger::mod_pow_monty`] with `convert = false`, for the
    /// Miller-Rabin squaring chain.
    fn mod_square_monty(b: &BigInteger, m: &BigInteger) -> BigInteger {
        let n = m.magnitude.len();
        let pow_r = 32 * n;
        let small_monty_modulus = (m.bit_length() as usize) + 2 <= pow_r;
        let m_prime = m.m_prime();
        let mut y_acc_m = vec![0u32; n + 1];

        // b 已在 Montgomery 域，左補零成剛好 n 字
        let z_val = b.magnitude.to_vec();
        debug_assert!(z_val.len() <= n);
        let mut y_val = vec![0u32; n];
        y_val[n - z_val.len()..].copy_from_slice(&z_val);

        square_monty(&mut y_acc_m, &mut y_val, &m.magnitude, m_prime, small_monty_modulus);

        if small_monty_modulus && compare_to(&y_val, &m.magnitude).is_ge() {
            sub_in_place(&mut y_val, &m.magnitude);
        }
        BigInteger::from_checked_magnitude(1, y_val)
    }

    /// Returns `|self| mod m` as a single word (sign ignored). `m` must be
    /// non-zero. Fast path for small-prime trial division.
    fn remainder_u32(&self, m: u32) -> u32 {
        debug_assert!(m > 0);
        let mut acc = 0u64;
        for &word in self.magnitude.iter() {
            acc = ((acc << 32) | word as u64) % m as u64; // 逐字帶餘數（big-endian）
        }
        acc as u32
    }

    /// Parses a `BigInteger` from a string in the given radix (`2..=36`).
    ///
    /// An optional leading `+`/`-` sign is allowed. Digits use `0-9` then
    /// `a-z`/`A-Z` (case-insensitive) up to the radix.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is not in `2..=36`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_str_radix("ff", 16).unwrap(), BigInteger::from_u32(255));
    /// assert_eq!(BigInteger::from_str_radix("-101", 2).unwrap(), BigInteger::from_i32(-5));
    /// ```
    pub fn from_str_radix(s: &str, radix: u32) -> Result<BigInteger, ParseBigIntegerError> {
        assert!((2..=36).contains(&radix), "radix must be in 2..=36, got {radix}");

        // 剝掉可選符號前綴；offset 記錄剝了幾個字元（供錯誤位置換算回原始 s）
        let (sign_neg, digits, offset) = if let Some(rest) = s.strip_prefix('-') {
            (true, rest, 1)
        } else if let Some(rest) = s.strip_prefix('+') {
            (false, rest, 1)
        } else {
            (false, s, 0)
        };

        if digits.is_empty() {
            return Err(ParseBigIntegerError::Empty); // "" / "-" / "+"
        }

        // TODO(效能): 目前逐字元，每位做一次大數乘法 → O(位數²) 且每位 3 次配置。
        //   可改分塊：一次吃 chunk 位（如十進制 19 位）用原生 u64 解析，再乘 radix^chunk，
        //   大乘次數少約 18 倍（仍 O(D²)，僅常數變小）。對密碼學尺寸目前夠用，暫不改。
        let radix_big = BigInteger::from_u32(radix);
        let mut result = BigInteger::from_u32(0);
        for (i, ch) in digits.chars().enumerate() {
            let d = ch.to_digit(radix).ok_or(ParseBigIntegerError::InvalidDigit {
                index: i + offset, // 換算回原始字串的位置
                ch,
            })?;
            // result = result * radix + d（radix 為 2 的次方時 Mul 自動走位移）
            result = &(&result * &radix_big) + &BigInteger::from_u32(d);
        }

        // 套符號；result 為 0 時 Neg 仍是 0（不會有負零）
        Ok(if sign_neg { -result } else { result })
    }

    /// Formats this value as a string in the given radix (`2..=36`).
    ///
    /// Negative values get a leading `-`. Digits use `0-9` then lowercase
    /// `a-z`. Inverse of [`BigInteger::from_str_radix`].
    ///
    /// # Panics
    ///
    /// Panics if `radix` is not in `2..=36`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32(255).to_str_radix(16), "ff");
    /// assert_eq!(BigInteger::from_i32(-5).to_str_radix(2), "-101");
    /// ```
    pub fn to_str_radix(&self, radix: u32) -> String {
        assert!((2..=36).contains(&radix), "radix must be in 2..=36, got {radix}");

        if self.sign == 0 {
            return "0".to_string();
        }

        // TODO(效能): 對稱於 from_str_radix，逐位一次大數 div_rem → O(位數²)。
        //   可分塊：除以 radix^chunk，一次把 u64 餘數格式化 chunk 位。暫不改。
        let radix_big = BigInteger::from_u32(radix);
        let mut n = BigInteger::new(1, self.magnitude.to_vec()); // |self|（正的複本）
        let mut digits = Vec::new(); // 低位在前
        while n.sign != 0 {
            let (q, r) = n.div_rem(&radix_big);
            let d = if r.sign == 0 { 0 } else { r.magnitude[0] }; // 餘數 0..radix-1
            digits.push(char::from_digit(d, radix).expect("digit < radix <= 36"));
            n = q;
        }

        let mut result = String::new();
        if self.sign < 0 {
            result.push('-');
        }
        result.extend(digits.iter().rev()); // 反轉成高位在前
        result
    }

    /// Returns the number of bits in the minimal two's-complement representation
    /// of this value, excluding the sign bit. Zero has a bit length of `0`.
    ///
    /// Recomputed on each call (O(1) for non-negative values); cache at the call
    /// site if you query the same value repeatedly on a hot path.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32(0).bit_length(), 0);
    /// assert_eq!(BigInteger::from_u32(5).bit_length(), 3); // 0b101
    /// assert_eq!(BigInteger::from_i32(-8).bit_length(), 3); // 負的 2 次方少 1
    /// ```
    pub fn bit_length(&self) -> u32 {
        calc_bit_length(self.sign, &self.magnitude)
    }

    /// Returns the number of bytes in the minimal two's-complement (signed)
    /// representation — the length [`BigInteger::to_bytes_be`] produces.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_i32(0).byte_length(), 1);
    /// assert_eq!(BigInteger::from_i32(128).byte_length(), 2); // 需符號位元組 → [00 80]
    /// assert_eq!(BigInteger::from_i32(-128).byte_length(), 1); // [80]
    /// ```
    pub fn byte_length(&self) -> usize {
        // bit_length() 已含符號與負 2 次方的處理；+1 容納符號位元。零 → 0/8+1 = 1
        self.bit_length() as usize / 8 + 1
    }

    /// Returns the number of bytes in the minimal unsigned (magnitude)
    /// representation — the length [`BigInteger::to_bytes_be_unsigned`] produces.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32(128).byte_length_unsigned(), 1); // [80]
    /// assert_eq!(BigInteger::from_u32(256).byte_length_unsigned(), 2); // [01 00]
    /// ```
    pub fn byte_length_unsigned(&self) -> usize {
        if self.sign == 0 {
            return 1; // 零輸出 [0]
        }
        // 只看 magnitude 的位元長度（sign=1 避開 bit_length 對負數的 quirk）
        (calc_bit_length(1, &self.magnitude) as usize).div_ceil(8)
    }

    /// Returns the number of bits in the two's-complement representation of this
    /// value that differ from the sign bit. For non-negative values this is the
    /// ordinary population count; for negative values it is `popcount(|n| - 1)`.
    ///
    /// Recomputed on each call (O(word count)); cache at the call site if you
    /// query the same value repeatedly on a hot path.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32(0b101).bit_count(), 2);
    /// assert_eq!(BigInteger::from_i32(-1).bit_count(), 0);
    /// assert_eq!(BigInteger::from_i32(-8).bit_count(), 3);
    /// ```
    pub fn bit_count(&self) -> u32 {
        if self.sign < 0 {
            // 負數：bitCount = popcount(|n| - 1)
            bit_count_negative(&self.magnitude)
        } else {
            self.magnitude.iter().map(|w| w.count_ones()).sum()
        }
    }

    /// 是否為 2 的次方（正數且僅一個設定位）。供 `Mul` 的 `<< k` 捷徑判斷。
    fn is_power_of_two(&self) -> bool {
        self.sign > 0 && self.bit_count() == 1
    }

    /// Returns `true` if bit `n` (zero-indexed, two's-complement) is set.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert!(BigInteger::from_u32(0b101).test_bit(0));
    /// assert!(!BigInteger::from_u32(0b101).test_bit(1));
    /// assert!(BigInteger::from_i32(-1).test_bit(99)); // -1 = ...1111，每位皆 1
    /// ```
    pub fn test_bit(&self, n: u32) -> bool {
        if self.sign < 0 {
            // 兩補數恆等式：x 為負時，第 n 位與 ~x（非負）的第 n 位相反
            return !self.not().test_bit(n);
        }
        let word_num = (n / u32::BITS) as usize;
        if word_num >= self.magnitude.len() {
            return false; // 超出 magnitude：正數更高位皆 0
        }
        // big-endian：低位字在尾端，取第 word_num 個低位字
        let word = self.magnitude[self.magnitude.len() - 1 - word_num];
        ((word >> (n % u32::BITS)) & 1) != 0
    }

    /// Returns this value with bit `n` set to 1.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32(0b101).set_bit(1), BigInteger::from_u32(0b111));
    /// ```
    pub fn set_bit(&self, n: u32) -> BigInteger {
        // 第 n 位設 1：self | (1 << n)
        self | &(&BigInteger::from_u32(1) << n)
    }

    /// Returns this value with bit `n` cleared to 0.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32(0b101).clear_bit(0), BigInteger::from_u32(0b100));
    /// ```
    pub fn clear_bit(&self, n: u32) -> BigInteger {
        // 第 n 位設 0：self & ~(1 << n)
        let mask = &BigInteger::from_u32(1) << n; // 1 << n
        let inv = !&mask; // ~(1 << n)
        self & &inv
    }

    /// Returns this value with bit `n` flipped.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32(0b101).flip_bit(2), BigInteger::from_u32(0b001));
    /// ```
    pub fn flip_bit(&self, n: u32) -> BigInteger {
        // 翻轉第 n 位：self ^ (1 << n)
        self ^ &(&BigInteger::from_u32(1) << n)
    }

    /// Returns the index of the lowest set bit (the number of trailing zero
    /// bits), or `None` if this value is zero.
    ///
    /// The sign is irrelevant: a value and its negation share the same lowest
    /// set bit, since two's-complement negation preserves trailing zeros.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32(0b1100).get_lowest_set_bit(), Some(2));
    /// assert_eq!(BigInteger::from_u32(1).get_lowest_set_bit(), Some(0));
    /// assert_eq!(BigInteger::from_u32(0).get_lowest_set_bit(), None);
    /// assert_eq!(BigInteger::from_i32(-12).get_lowest_set_bit(), Some(2));
    /// ```
    pub fn get_lowest_set_bit(&self) -> Option<u32> {
        // 從低位端（尾端）掃第一個非零字，回「跳過的零字 × 32 + 字內 trailing_zeros」。
        // 符號無關；零的 magnitude 為空 → iter 空 → 自然回 None。
        self.magnitude
            .iter()
            .rev()
            .enumerate()
            .find(|&(_, &w)| w != 0)
            .map(|(i, &w)| i as u32 * u32::BITS + w.trailing_zeros())
    }

    /// Returns the bitwise AND of `self` with the complement of `other`
    /// (`self & !other`), in two's-complement semantics.
    ///
    /// Clears every bit of `self` that is set in `other` — a convenient
    /// "mask off" operation.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let a = BigInteger::from_u32(0b1110);
    /// let b = BigInteger::from_u32(0b0110);
    /// assert_eq!(a.and_not(&b), BigInteger::from_u32(0b1000)); // 清掉 b 有的位元
    /// ```
    pub fn and_not(&self, other: &BigInteger) -> BigInteger {
        // 直接複用既有 operator：!other 走 Not，再與 self 做 BitAnd
        self & &!other
    }

    /// Creates a `BigInteger` from an unsigned 32-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u32(5);
    /// ```
    pub fn from_u32(value: u32) -> Self {
        if value == 0 {
            BigInteger::new(0, Vec::new())
        } else {
            BigInteger::new(1, vec![value])
        }
    }

    /// Creates a `BigInteger` from an unsigned 16-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u16(5);
    /// ```
    pub fn from_u16(value: u16) -> Self {
        BigInteger::from_u32(u32::from(value))
    }

    /// Creates a `BigInteger` from an unsigned 8-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u8(5);
    /// ```
    pub fn from_u8(value: u8) -> Self {
        BigInteger::from_u32(u32::from(value))
    }

    /// Creates a `BigInteger` from an unsigned 64-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u64(5);
    /// ```
    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            return BigInteger::new(0, Vec::new());
        }
        let high = (value >> 32) as u32;
        let low = value as u32;
        // Big-endian, no leading zero word: drop the high word when it is zero.
        let magnitude = if high == 0 { vec![low] } else { vec![high, low] };
        BigInteger::new(1, magnitude)
    }

    /// Creates a `BigInteger` from a signed 32-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_i32(-5);
    /// ```
    pub fn from_i32(value: i32) -> Self {
        if value == 0 {
            return BigInteger::new(0, Vec::new());
        }
        let sign = if value < 0 { -1 } else { 1 };
        // `unsigned_abs` yields the magnitude as `u32`, avoiding overflow on `i32::MIN`.
        BigInteger::new(sign, vec![value.unsigned_abs()])
    }

    /// Creates a `BigInteger` from a signed 16-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_i16(-5);
    /// ```
    pub fn from_i16(value: i16) -> Self {
        BigInteger::from_i32(i32::from(value))
    }

    /// Creates a `BigInteger` from a signed 8-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_i8(-5);
    /// ```
    pub fn from_i8(value: i8) -> Self {
        BigInteger::from_i32(i32::from(value))
    }

    /// Creates a `BigInteger` from a signed 64-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_i64(-5);
    /// ```
    pub fn from_i64(value: i64) -> Self {
        if value == 0 {
            return BigInteger::new(0, Vec::new());
        }
        // `unsigned_abs` avoids overflow on `i64::MIN`; reuse `from_u64`'s word split.
        let magnitude = Vec::from(BigInteger::from_u64(value.unsigned_abs()).magnitude);
        let sign = if value < 0 { -1 } else { 1 };
        BigInteger::new(sign, magnitude)
    }

    /// Creates a `BigInteger` from a signed 128-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_i128(-5);
    /// ```
    pub fn from_i128(value: i128) -> Self {
        if value == 0 {
            return BigInteger::new(0, Vec::new());
        }
        // `unsigned_abs` avoids overflow on `i128::MIN`; reuse `from_u128`'s word split.
        let magnitude = Vec::from(BigInteger::from_u128(value.unsigned_abs()).magnitude);
        let sign = if value < 0 { -1 } else { 1 };
        BigInteger::new(sign, magnitude)
    }

    /// Creates a `BigInteger` from an unsigned 128-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u128(5);
    /// ```
    pub fn from_u128(value: u128) -> Self {
        if value == 0 {
            return BigInteger::new(0, Vec::new());
        }
        // Split into 4 big-endian words (most-significant first).
        let words = [
            (value >> 96) as u32,
            (value >> 64) as u32,
            (value >> 32) as u32,
            value as u32,
        ];
        // Skip leading zero words. `value != 0` guarantees at least one non-zero.
        let start = words.iter().position(|&w| w != 0).unwrap();
        BigInteger::new(1, words[start..].to_vec())
    }

    /// Returns a uniformly random non-negative integer in `[0, 2^bit_length)`
    /// (zero when `bit_length == 0`).
    ///
    /// `⌈bit_length / 8⌉` random bytes are drawn from `rng`, and the excess high
    /// bits of the top byte are masked off, so the result has at most
    /// `bit_length` bits. The RNG is supplied by the caller; pass a
    /// cryptographically secure source when the value must be unpredictable.
    ///
    /// Corresponds to `BigIntegers.CreateRandomBigInteger` in Bouncy Castle.
    pub fn random_bits(bit_length: u32, rng: &mut dyn Rng) -> BigInteger {
        if bit_length == 0 {
            return BigInteger::from_u32(0);
        }
        let n_bytes = bit_length.div_ceil(8) as usize; // ⌈bit_length / 8⌉
        let mut bytes = vec![0u8; n_bytes];
        rng.fill_bytes(&mut bytes);
        // 遮掉最高位元組多出來的高位，使總位元數 ≤ bit_length
        let excess = 8 * n_bytes as u32 - bit_length; // 0..=7
        bytes[0] &= 0xFFu8 >> excess;
        BigInteger::from_bytes_be_unsigned(&bytes)
    }

}

impl PartialEq for BigInteger {
    /// 相等只看數值（`sign` + `magnitude`）。
    fn eq(&self, other: &Self) -> bool {
        self.sign == other.sign && self.magnitude == other.magnitude
    }
}

impl Eq for BigInteger {}

impl Hash for BigInteger {
    /// Hashes the numeric value (`sign` + `magnitude`), matching [`PartialEq`]. The
    /// no-leading-zeros invariant makes the magnitude canonical, so equal values
    /// always hash equally.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sign.hash(state);
        self.magnitude.hash(state);
    }
}

impl Ord for BigInteger {
    fn cmp(&self, other: &Self) -> Ordering {
        // 符號不同：負 < 零 < 正，直接由符號決定
        if self.sign != other.sign {
            return self.sign.cmp(&other.sign);
        }
        // 同號（含兩者皆零，magnitude 皆空 → Equal）：比絕對值，負號時翻轉
        let mag = compare_magnitude(&self.magnitude, &other.magnitude);
        if self.sign < 0 { mag.reverse() } else { mag }
    }
}

impl PartialOrd for BigInteger {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other)) // 全序，永遠有結果
    }
}

impl BigInteger {
    /// 與原生整數的零配置比較核心：把對方拆成 `(符號, 絕對值)` 後，直接對
    /// `self.sign`／`self.magnitude` 比，不建立暫時 `BigInteger`。邏輯同 [`Ord::cmp`]。
    ///
    /// 任何原生整數的絕對值都塞得進 `u128`（含 `i128::MIN` 的 2¹²⁷、`u128::MAX`），
    /// 故 `other_abs` 用 `u128` 即可涵蓋所有型別。
    fn cmp_scalar(&self, other_sign: i32, other_abs: u128) -> Ordering {
        // 符號不同：負 < 零 < 正，直接由符號決定
        if self.sign != other_sign {
            return self.sign.cmp(&other_sign);
        }
        // 同號（含兩者皆零 → Equal）：比絕對值，負號時翻轉
        let mag = self.cmp_abs_u128(other_abs);
        if self.sign < 0 { mag.reverse() } else { mag }
    }

    /// 比較 `|self|` 與一個 `u128` 絕對值。`magnitude` 為 big-endian、無前導零的 u32 詞。
    fn cmp_abs_u128(&self, abs: u128) -> Ordering {
        if self.magnitude.len() > 4 {
            return Ordering::Greater; // > 4 字即 ≥ 2¹²⁸，大於任何 u128
        }
        // ≤ 4 字塞得進 u128：組出低位到高位的值後直接比（空 magnitude → 0）
        let mut acc: u128 = 0;
        for &w in self.magnitude.iter() {
            acc = (acc << 32) | w as u128;
        }
        acc.cmp(&abs)
    }
}

// 為所有原生整數型別實作與 BigInteger 的零配置比較（`big == 5`、`big < 0u64` 等）。
// 只提供 `BigInteger <op> {int}` 方向；`{int} <op> BigInteger`（整數在左）需在各整數
// 型別上另補鏡像 impl。PartialOrd<T> 的父 trait PartialEq<T> 一併展開。
macro_rules! impl_cmp_int_signed {
    ($($t:ty),+ $(,)?) => {$(
        impl PartialEq<$t> for BigInteger {
            fn eq(&self, other: &$t) -> bool {
                self.cmp_scalar((*other).signum() as i32, (*other).unsigned_abs() as u128) == Ordering::Equal
            }
        }
        impl PartialOrd<$t> for BigInteger {
            fn partial_cmp(&self, other: &$t) -> Option<Ordering> {
                Some(self.cmp_scalar((*other).signum() as i32, (*other).unsigned_abs() as u128))
            }
        }
    )+};
}

macro_rules! impl_cmp_int_unsigned {
    ($($t:ty),+ $(,)?) => {$(
        impl PartialEq<$t> for BigInteger {
            fn eq(&self, other: &$t) -> bool {
                self.cmp_scalar(if *other == 0 { 0 } else { 1 }, *other as u128) == Ordering::Equal
            }
        }
        impl PartialOrd<$t> for BigInteger {
            fn partial_cmp(&self, other: &$t) -> Option<Ordering> {
                Some(self.cmp_scalar(if *other == 0 { 0 } else { 1 }, *other as u128))
            }
        }
    )+};
}

impl_cmp_int_signed!(i8, i16, i32, i64, i128, isize);
impl_cmp_int_unsigned!(u8, u16, u32, u64, u128, usize);

impl Neg for BigInteger {
    type Output = BigInteger;

    /// 取負：只翻轉符號，magnitude 長度不變，故直接搬移（重用）buffer。
    fn neg(self) -> BigInteger {
        // `Vec::from` 接手 Box 的配置（O(1)），`new` 再 `into_boxed_slice` 收回（O(1)）；
        // 全程無新配置。
        BigInteger::new(-self.sign, Vec::from(self.magnitude))
    }
}

impl Neg for &BigInteger {
    type Output = BigInteger;

    fn neg(self) -> BigInteger {
        BigInteger::new(-self.sign, Vec::from(&*self.magnitude))
    }
}

impl Not for &BigInteger {
    type Output = BigInteger;

    /// 位元 NOT（兩補數）：`!x = -(x + 1)`。
    fn not(self) -> BigInteger {
        // self + 1 產生 owned 暫時值，接著的一元 `-` 命中 owned Neg，
        // 直接重用該暫時值的 buffer；整條 `!x` 只有 `+` 那次配置。
        -(self + &BigInteger::from_u32(1))
    }
}

impl BitAnd for &BigInteger {
    type Output = BigInteger;

    /// 位元 AND（兩補數語義）。負 AND 負 → 負。
    fn bitand(self, rhs: &BigInteger) -> BigInteger {
        if self.sign == 0 || rhs.sign == 0 {
            return BigInteger::from_u32(0); // x & 0 = 0
        }
        bitwise(self, rhs, self.sign < 0 && rhs.sign < 0, |a, b| a & b)
    }
}

impl BitOr for &BigInteger {
    type Output = BigInteger;

    /// 位元 OR（兩補數語義）。負 OR 任意 → 負。
    fn bitor(self, rhs: &BigInteger) -> BigInteger {
        if self.sign == 0 {
            return rhs.clone(); // 0 | x = x
        }
        if rhs.sign == 0 {
            return self.clone(); // x | 0 = x
        }
        bitwise(self, rhs, self.sign < 0 || rhs.sign < 0, |a, b| a | b)
    }
}

impl BitXor for &BigInteger {
    type Output = BigInteger;

    /// 位元 XOR（兩補數語義）。符號相異 → 負。
    fn bitxor(self, rhs: &BigInteger) -> BigInteger {
        if self.sign == 0 {
            return rhs.clone(); // 0 ^ x = x
        }
        if rhs.sign == 0 {
            return self.clone(); // x ^ 0 = x
        }
        bitwise(self, rhs, (self.sign < 0) != (rhs.sign < 0), |a, b| a ^ b)
    }
}

impl Add for &BigInteger {
    type Output = BigInteger;

    fn add(self, rhs: &BigInteger) -> BigInteger {
        if self.sign == 0 {
            rhs.clone()
        } else if rhs.sign == 0 {
            self.clone()
        } else if self.sign == rhs.sign {
            // 同號：magnitude 相加，沿用符號
            BigInteger::new(self.sign, add_magnitudes(&self.magnitude, &rhs.magnitude))
        } else if rhs.sign < 0 {
            self - &(-rhs)
        } else {
            rhs - &(-self)
        }
    }
}

impl Sub for &BigInteger {
    type Output = BigInteger;

    fn sub(self, rhs: &BigInteger) -> BigInteger {
        if rhs.sign == 0 {
            self.clone()
        } else if self.sign == 0 {
            -rhs
        } else if self.sign != rhs.sign {
            self + &(-rhs)
        } else {
            // 同號：比 magnitude，大減小，結果符號 = 較大者的符號
            match compare_magnitude(&self.magnitude, &rhs.magnitude) {
                Ordering::Equal => BigInteger::from_u32(0),
                Ordering::Greater => {
                    BigInteger::new(self.sign, sub_magnitudes(&self.magnitude, &rhs.magnitude))
                }
                Ordering::Less => {
                    BigInteger::new(-self.sign, sub_magnitudes(&rhs.magnitude, &self.magnitude))
                }
            }
        }
    }
}

impl Mul for &BigInteger {
    type Output = BigInteger;

    fn mul(self, rhs: &BigInteger) -> BigInteger {
        if self.sign == 0 || rhs.sign == 0 {
            return BigInteger::from_u32(0);
        }
        let sign = self.sign * rhs.sign;

        // 捷徑 1：某運算元為 2^k → 乘法退化成 << k（k = bit_length - 1）
        if self.is_power_of_two() {
            let magnitude = shift_left_magnitude(&rhs.magnitude, (self.bit_length() - 1) as usize);
            return BigInteger::new(sign, magnitude);
        }
        if rhs.is_power_of_two() {
            let magnitude = shift_left_magnitude(&self.magnitude, (rhs.bit_length() - 1) as usize);
            return BigInteger::new(sign, magnitude);
        }

        // 捷徑 2：同一份運算元（`&x * &x`）→ 平方（~2 倍快）。
        // 其餘走 schoolbook；Karatsuba 之類的大數最佳化留待日後。
        let magnitude = if core::ptr::eq(self, rhs) {
            square_magnitude(&self.magnitude)
        } else {
            multiply_magnitudes(&self.magnitude, &rhs.magnitude)
        };
        BigInteger::new(sign, magnitude)
    }
}

impl Div for &BigInteger {
    type Output = BigInteger;

    /// 截斷除法的商（見 [`BigInteger::div_rem`]）。除數為 0 時 panic。
    fn div(self, rhs: &BigInteger) -> BigInteger {
        self.div_rem(rhs).0
    }
}

impl Rem for &BigInteger {
    type Output = BigInteger;

    /// 截斷除法的餘數（見 [`BigInteger::div_rem`]）。除數為 0 時 panic。
    fn rem(self, rhs: &BigInteger) -> BigInteger {
        self.div_rem(rhs).1
    }
}

impl FromStr for BigInteger {
    type Err = ParseBigIntegerError;

    /// Parses in radix 10（讓 `"123".parse::<BigInteger>()` 可用）。
    fn from_str(s: &str) -> Result<BigInteger, ParseBigIntegerError> {
        BigInteger::from_str_radix(s, 10)
    }
}

impl core::fmt::Display for BigInteger {
    /// 十進制輸出（委派 `to_str_radix(10)`）；`{}`、`to_string()` 皆走此。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_str_radix(10))
    }
}

impl Shl<u32> for &BigInteger {
    type Output = BigInteger;

    /// 左移 `n` 位（相當於乘以 `2^n`）。
    fn shl(self, n: u32) -> BigInteger {
        if self.sign == 0 || n == 0 {
            return self.clone(); // 0 << n = 0；x << 0 = x
        }
        // 左移不改符號；magnitude 交給 helper（u32 位元量 → usize 供索引）
        let magnitude = shift_left_magnitude(&self.magnitude, n as usize);
        BigInteger::new(self.sign, magnitude)
    }
}

impl Shr<u32> for &BigInteger {
    type Output = BigInteger;

    /// 右移 `n` 位（算術右移：等同 `floor(self / 2^n)`，向負無窮取整）。
    ///
    /// 非負數等同截斷；負數若移出的低位有非零，會再向下多退一（floor 修正）。
    fn shr(self, n: u32) -> BigInteger {
        if self.sign == 0 || n == 0 {
            return self.clone(); // 0 >> n = 0；x >> 0 = x
        }
        let n = n as usize;

        // 移出位元數超過整個 magnitude 容量：非負 → 0；負 → -1（floor 落在 -1）
        let total_bits = self.magnitude.len() * WORD_BITS;
        if n >= total_bits {
            return if self.sign < 0 {
                BigInteger::from_i32(-1)
            } else {
                BigInteger::from_u32(0)
            };
        }

        let mut magnitude = shift_right_magnitude(&self.magnitude, n);

        // 負數 floor 修正：截斷往零靠，若真的丟了低位，需往負無窮再多退一
        if self.sign < 0 && any_low_bits_set(&self.magnitude, n) {
            magnitude = add_magnitudes(&magnitude, &[1]);
        }

        // 正數可能移空 → 0；負數經上面修正後必非空
        let sign = if magnitude.is_empty() { 0 } else { self.sign };
        BigInteger::new(sign, magnitude)
    }
}

/// 為每個固定寬度整數型別生成無損的 `From<$t> for BigInteger`，委派給對應建構函式。
macro_rules! impl_from_primitive {
    ($($t:ty => $ctor:ident),* $(,)?) => {
        $(
            impl From<$t> for BigInteger {
                /// 無損轉換（固定寬度整數必可表示）。
                fn from(value: $t) -> Self {
                    BigInteger::$ctor(value)
                }
            }
        )*
    };
}

impl_from_primitive! {
    u8 => from_u8, u16 => from_u16, u32 => from_u32, u64 => from_u64, u128 => from_u128,
    i8 => from_i8, i16 => from_i16, i32 => from_i32, i64 => from_i64, i128 => from_i128,
}

/// 為每個無號整數型別生成 `TryFrom<&BigInteger>`：負數或超出範圍回 `Err`。
macro_rules! impl_try_from_big_unsigned {
    ($($t:ty),* $(,)?) => {
        $(
            impl TryFrom<&BigInteger> for $t {
                type Error = TryFromBigIntegerError;

                fn try_from(value: &BigInteger) -> Result<$t, TryFromBigIntegerError> {
                    if value.sign() < 0 {
                        return Err(TryFromBigIntegerError(())); // 負數無法轉無號
                    }
                    const BYTES: usize = size_of::<$t>();
                    let n = value.byte_length_unsigned();
                    if n > BYTES {
                        return Err(TryFromBigIntegerError(())); // 位元組數超出目標
                    }
                    // magnitude 位元組右對齊寫進固定寬度 buffer，上方補 0
                    let mut buf = [0u8; BYTES];
                    value.to_bytes_be_unsigned_into(&mut buf[BYTES - n..]);
                    Ok(<$t>::from_be_bytes(buf))
                }
            }
        )*
    };
}

/// 為每個有號整數型別生成 `TryFrom<&BigInteger>`：超出範圍回 `Err`。
macro_rules! impl_try_from_big_signed {
    ($($t:ty),* $(,)?) => {
        $(
            impl TryFrom<&BigInteger> for $t {
                type Error = TryFromBigIntegerError;

                fn try_from(value: &BigInteger) -> Result<$t, TryFromBigIntegerError> {
                    const BYTES: usize = size_of::<$t>();
                    let n = value.byte_length();
                    if n > BYTES {
                        return Err(TryFromBigIntegerError(()));
                    }
                    // 兩補數位元組右對齊寫入；上方以符號延伸填滿（負 0xFF、非負 0x00）
                    let mut buf = if value.sign() < 0 { [0xFFu8; BYTES] } else { [0u8; BYTES] };
                    value.to_bytes_be_into(&mut buf[BYTES - n..]);
                    Ok(<$t>::from_be_bytes(buf))
                }
            }
        )*
    };
}

impl_try_from_big_unsigned!(u8, u16, u32, u64, u128);
impl_try_from_big_signed!(i8, i16, i32, i64, i128);

/// 計算 magnitude（big-endian、無前導零）的位元長度，不含符號位。
fn calc_bit_length(sign: i32, magnitude: &[u32]) -> u32 {
    // 無前導零，故第一個字即最高位字；空 magnitude 代表 0
    let Some((&first, rest)) = magnitude.split_first() else {
        return 0;
    };

    // 低位每個滿字貢獻 u32::BITS 位，加上最高位字的有效位數
    let mut bit_length = u32::BITS * rest.len() as u32 + bit_len(first);

    // 負的 2 次方（整個 magnitude 只有單一設定位元）時，少 1 位
    if sign < 0 && first.is_power_of_two() && rest.iter().all(|&w| w == 0) {
        bit_length -= 1;
    }
    bit_length
}

/// 單一字的位元長度（最高設定位元的位置 + 1）；`x` 為 0 時得 0。
fn bit_len(x: u32) -> u32 {
    u32::BITS - x.leading_zeros()
}

/// 把一個視窗編碼成 `mul_t | (zeros << 8)`：`mul_t` 正規化成奇數，拆出的尾端
/// 零併進 `zeros`（= 這個視窗之後要補幾次平方）。供滑動視窗指數化使用。
fn create_window_entry(mut mul_t: u32, mut zeros: u32) -> u32 {
    debug_assert!(mul_t > 0);
    let tz = mul_t.trailing_zeros();
    mul_t >>= tz;
    zeros += tz;
    mul_t | (zeros << 8)
}

/// 從高位到低位掃描指數 `mag`（big-endian，MSW 在前），拆成一串視窗項，最後
/// 以 `u32::MAX` 收尾。每項含「奇數乘數 `mul_t`」與「後續零平方次數 `zeros`」，
/// 由 [`create_window_entry`] 編碼；`extra_bits` 決定視窗最大寬度（`2^extra_bits`）。
fn get_window_list(mag: &[u32], extra_bits: usize) -> Vec<u32> {
    let mut v = mag[0];
    debug_assert!(v != 0);
    let leading_bits = bit_len(v) as usize;
    let total_bits = ((mag.len() - 1) << 5) + leading_bits;
    let result_size = (total_bits + extra_bits) / (1 + extra_bits) + 1;
    let mut result = vec![0u32; result_size];
    let mut result_pos = 0;
    let mut bit_pos = 33 - leading_bits;
    v = v.wrapping_shl(bit_pos as u32);

    let mut mul_t = 1u32;
    let mul_t_limit = 1u32 << extra_bits;
    let mut zeros = 0u32;

    let mut i = 0;
    loop {
        while bit_pos < 32 {
            bit_pos += 1;
            if mul_t < mul_t_limit {
                mul_t = (mul_t << 1) | (v >> 31);
            } else if (v as i32) < 0 {
                // mul_t 已滿寬且下一位為 1 → 收掉當前視窗，另起新的
                result[result_pos] = create_window_entry(mul_t, zeros);
                result_pos += 1;
                mul_t = 1;
                zeros = 0;
            } else {
                zeros += 1; // 下一位為 0 → 累積一次平方
            }
            v <<= 1;
        }
        i += 1;
        if i == mag.len() {
            result[result_pos] = create_window_entry(mul_t, zeros);
            result_pos += 1;
            break;
        }
        v = mag[i];
        bit_pos = 0;
    }
    result[result_pos] = u32::MAX;
    result
}

/// 奇數 `d` 在 mod 2³² 的反元素：`d · inverse_u32(d) ≡ 1 (mod 2³²)`。
/// Newton 迭代 `x ← x·(2 − d·x)`，每步正確低位位元數翻倍（3→6→12→24→48），
/// 4 步蓋過 32 位。`wrapping_mul` 天然即 mod 2³²，無需另取模。
fn inverse_u32(d: u32) -> u32 {
    debug_assert!(d & 1 == 1);
    let mut x = d; // 種子：奇數自逆 mod 8（d·d ≡ 1 mod 8）
    x = x.wrapping_mul(2u32.wrapping_sub(d.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(d.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(d.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(d.wrapping_mul(x)));
    x
}

/// 單字（n=1）Montgomery 乘法：回傳 `x·y·R⁻¹ mod m`（R = 2³²）。
/// `m` 為奇 u32；`m_prime = -m⁻¹ mod 2³²`（見 [`BigInteger::m_prime`]）。
fn multiply_monty_n_is_one(x: u32, y: u32, m: u32, m_prime: u32) -> u32 {
    let mut carry = x as u64 * y as u64; // 完整乘積
    let t = (carry as u32).wrapping_mul(m_prime); // 選 t 使加上 t·m 後低 32 位歸零
    let um = m as u64;
    let prod2 = um * t as u64; // t·m
    carry += (prod2 as u32) as u64;
    debug_assert!(carry as u32 == 0); // 低 32 位確實被消掉（Montgomery 不變量）
    carry = (carry >> 32) + (prod2 >> 32); // = (x·y + t·m) / 2³²，落在 [0, 2m)
    if carry >= um {
        carry -= um; // 最終條件減至 [0, m)（標準 Montgomery：>=，非 >）
    }
    debug_assert!(carry < um);
    carry as u32
}

/// 多字 Montgomery 乘法：`x ← x·y·R⁻¹ mod m`（原地寫回 `x`），R = 2^(32·n)。
///
/// `a` 是長度 `n+1` 的暫存累加器；`x`/`y`/`m` 各 `n` 字（big-endian，且 `x,y < m`）；
/// `m_prime = -m⁻¹ mod 2³²`。`small_monty_modulus` 為真時省略最終條件減（頂端有餘裕，
/// 由呼叫端統一處理）。邊乘邊約簡（CIOS），全程只有乘法與位移，無長除法。
fn multiply_monty(a: &mut [u32], x: &mut [u32], y: &[u32], m: &[u32], m_prime: u32, small_monty_modulus: bool) {
    let n = m.len();
    if n == 1 {
        x[0] = multiply_monty_n_is_one(x[0], y[0], m[0], m_prime);
        return;
    }

    let y0 = y[n - 1];
    let mut a_max: u32;
    {
        // 第 0 輪：用 x 的最低字掃 y，同時算約簡乘數 t 並消掉低字
        let xi = x[n - 1] as u64;

        let mut carry = xi * y0 as u64;
        let t = (carry as u32).wrapping_mul(m_prime) as u64;

        let mut prod2 = t.wrapping_mul(m[n - 1] as u64);
        carry += (prod2 as u32) as u64;
        debug_assert!(carry as u32 == 0);
        carry = (carry >> 32) + (prod2 >> 32);

        for j in (0..=(n - 2)).rev() {
            let prod1 = xi * y[j] as u64;
            prod2 = t.wrapping_mul(m[j] as u64);

            carry += (prod1 & 0xFFFF_FFFF) + (prod2 as u32) as u64;
            a[j + 2] = carry as u32;
            carry = (carry >> 32) + (prod1 >> 32) + (prod2 >> 32);
        }

        a[1] = carry as u32;
        a_max = (carry >> 32) as u32;
    }

    for i in (0..=(n - 2)).rev() {
        // 第 i 輪：把 x[i]·y 累加進 a，並用 t·m 消掉新的低字
        let a0 = a[n];
        let xi = x[i] as u64;
        let mut prod1 = xi * y0 as u64;
        let mut carry = (prod1 & 0xFFFF_FFFF) + a0 as u64;
        let t = (carry as u32).wrapping_mul(m_prime) as u64;

        let mut prod2 = t.wrapping_mul(m[n - 1] as u64);
        carry += (prod2 as u32) as u64;
        debug_assert!(carry as u32 == 0);
        carry = (carry >> 32) + (prod1 >> 32) + (prod2 >> 32);

        for j in (0..=(n - 2)).rev() {
            prod1 = xi * y[j] as u64;
            prod2 = t.wrapping_mul(m[j] as u64);

            carry += (prod1 & 0xFFFF_FFFF) + (prod2 as u32) as u64 + a[j + 1] as u64;
            a[j + 2] = carry as u32;
            carry = (carry >> 32) + (prod1 >> 32) + (prod2 >> 32);
        }

        carry += a_max as u64;
        a[1] = carry as u32;
        a_max = (carry >> 32) as u32;
    }

    a[0] = a_max;
    if !small_monty_modulus && compare_to(a, m).is_ge() {
        sub_in_place(a, m); // 最終條件減至 [0, m)
    }
    x[0..n].copy_from_slice(&a[1..(n + 1)]); // 丟掉溢位字 a[0]，結果寫回 x
}

/// 多字 Montgomery 平方：`x ← x²·R⁻¹ mod m`（原地）。等同 `multiply_monty(x, x, …)`，
/// 但利用「交叉項 x_i·x_j 出現兩次」只算一半再 `×2`（`<<1` 配 `>>31` 帶進位）省一半乘法。
/// 參數語義同 [`multiply_monty`]。
///
/// 註：bak 以 `i32` 索引來讓 `0..=(i-1)` 在 `i=0` 時為空；此處改用 usize 的 `0..i`
/// 等價範圍，避免下溢。
fn square_monty(a: &mut [u32], x: &mut [u32], m: &[u32], m_prime: u32, small_monty_modulus: bool) {
    let n = m.len();
    if n == 1 {
        let x_val = x[0];
        x[0] = multiply_monty_n_is_one(x_val, x_val, m[0], m_prime);
        return;
    }

    let x0 = x[n - 1] as u64;
    let mut a_max: u32;
    {
        let mut carry = x0 * x0;
        let t = (carry as u32).wrapping_mul(m_prime) as u64;

        let mut prod2 = t.wrapping_mul(m[n - 1] as u64);
        carry += (prod2 as u32) as u64;
        debug_assert!(carry as u32 == 0);
        carry = (carry >> 32) + (prod2 >> 32);

        for j in (0..(n - 1)).rev() {
            let prod1 = x0 * x[j] as u64;
            prod2 = t.wrapping_mul(m[j] as u64);

            carry += (prod2 & 0xFFFF_FFFF) + ((prod1 as u32) << 1) as u64;
            a[j + 2] = carry as u32;
            carry = (carry >> 32) + (prod1 >> 31) + (prod2 >> 32);
        }

        a[1] = carry as u32;
        a_max = (carry >> 32) as u32;
    }

    for i in (0..(n - 1)).rev() {
        let a0 = a[n];
        let t = a0.wrapping_mul(m_prime) as u64;
        let mut carry = t.wrapping_mul(m[n - 1] as u64).wrapping_add(a0 as u64);
        debug_assert!(carry as u32 == 0);
        carry >>= 32;

        for j in ((i + 1)..(n - 1)).rev() {
            carry += t * m[j] as u64 + a[j + 1] as u64;
            a[j + 2] = carry as u32;
            carry >>= 32;
        }

        let xi = x[i] as u64;
        {
            let prod1 = xi * xi; // 對角項 x_i²（不乘 2）
            let prod2 = t.wrapping_mul(m[i] as u64);

            carry += (prod1 & 0xFFFF_FFFF) + (prod2 as u32) as u64 + a[i + 1] as u64;
            a[i + 2] = carry as u32;
            carry = (carry >> 32) + (prod1 >> 32) + (prod2 >> 32);
        }

        for j in (0..i).rev() {
            let prod1 = xi * x[j] as u64; // 交叉項 x_i·x_j（乘 2）
            let prod2 = t * m[j] as u64;

            carry += (prod2 & 0xFFFF_FFFF) + ((prod1 as u32) << 1) as u64 + a[j + 1] as u64;
            a[j + 2] = carry as u32;
            carry = (carry >> 32) + (prod1 >> 31) + (prod2 >> 32);
        }

        carry += a_max as u64;
        a[1] = carry as u32;
        a_max = (carry >> 32) as u32;
    }

    a[0] = a_max;

    if !small_monty_modulus && compare_to(a, m).is_ge() {
        sub_in_place(a, m);
    }

    x[0..n].copy_from_slice(&a[1..(n + 1)]);
}

/// Montgomery reduction：`x ← x·R⁻¹ mod m`（原地），把 Montgomery 域的值轉回普通形式。
/// 要求 `x.len() == m.len() == n` 且 `x < m`（非通用約簡，不收雙倍長度輸入）。
/// 逐字用 `t·m` 消掉低字再右移一字，共 n 輪。
fn montgomery_reduce(x: &mut [u32], m: &[u32], m_prime: u32) {
    debug_assert!(x.len() == m.len());
    let n = m.len();

    for _ in 0..n {
        let x0 = x[n - 1];
        let t = x0.wrapping_mul(m_prime) as u64;

        let mut carry = t * m[n - 1] as u64 + x0 as u64;
        debug_assert!(carry as u32 == 0); // 低字被消掉
        carry >>= 32;

        if n >= 2 {
            for j in (0..(n - 1)).rev() {
                carry += t * m[j] as u64 + x[j] as u64;
                x[j + 1] = carry as u32;
                carry >>= 32;
            }
        }

        x[0] = carry as u32;
        debug_assert!(carry >> 32 == 0);
    }

    // 結果落在 [0, m]，用 >= 修正到 [0, m)（bak 用 >，結果恰為 m 時會漏減）
    if compare_to(x, m).is_ge() {
        sub_in_place(x, m);
    }
}

/// 比較兩個 magnitude（big-endian、無前導零）代表的絕對值大小。
fn compare_magnitude(x: &[u32], y: &[u32]) -> Ordering {
    // 無前導零：字數多者絕對值大；字數相同再逐字（最高位在前）比字典序
    x.len().cmp(&y.len()).then_with(|| x.cmp(y))
}

/// 比較兩個可能帶前導零字的 magnitude（如 Montgomery 的定長 buffer）：
/// 先各自跳過前導零，再交給 [`compare_magnitude`]（後者要求無前導零）。
fn compare_to(x: &[u32], y: &[u32]) -> Ordering {
    let x = &x[x.iter().position(|&w| w != 0).unwrap_or(x.len())..];
    let y = &y[y.iter().position(|&w| w != 0).unwrap_or(y.len())..];
    compare_magnitude(x, y)
}

/// 去除 big-endian magnitude 的前導零字。
fn trim_leading_zeros(mut v: Vec<u32>) -> Vec<u32> {
    let start = v.iter().position(|&w| w != 0).unwrap_or(v.len());
    v.drain(..start);
    v
}

/// 原地加法：`x += y`（big-endian，低位對齊）。
///
/// 前提：`x.len() >= y.len()`，且 `x` 已預留足夠長度容納進位（最高位不溢出）。
/// 供除法內圈與 `add_magnitudes` 使用，避免每次相加都配置。
fn add_in_place(x: &mut [u32], y: &[u32]) {
    debug_assert!(x.len() >= y.len(), "add_in_place 需要 x.len() >= y.len()");

    let mut carry = 0u64;
    let mut xi = x.len();

    // 先把 y 逐字加進 x 的低位端（兩者尾端對齊），進位隨 u64 高位帶著走
    for &yw in y.iter().rev() {
        xi -= 1;
        carry += x[xi] as u64 + yw as u64;
        x[xi] = carry as u32;
        carry >>= 32;
    }
    // 剩餘進位繼續往更高位傳（xi > 0 護欄避免下溢，並讓下方 assert 給清楚訊息）
    while carry != 0 && xi > 0 {
        xi -= 1;
        carry += x[xi] as u64;
        x[xi] = carry as u32;
        carry >>= 32;
    }

    debug_assert!(carry == 0, "add_in_place 溢位：x 未預留足夠長度");
}

/// 兩個 magnitude（big-endian、無前導零）相加，回傳結果（無前導零）。
fn add_magnitudes(x: &[u32], y: &[u32]) -> Vec<u32> {
    let (long, short) = if x.len() >= y.len() { (x, y) } else { (y, x) };

    // 預留一個前導 0 字容納最高位進位；長者放進 result[1..]
    let mut result = vec![0u32; long.len() + 1];
    result[1..].copy_from_slice(long);

    add_in_place(&mut result, short); // 加法與進位傳遞交給原地核心；前導 0 字吸收進位
    trim_leading_zeros(result)
}

/// 兩個 magnitude（big-endian、無前導零）相減，回傳 `x - y`（無前導零）。
///
/// 前提：數值上 `x >= y`（呼叫端用 `compare_magnitude` 確保），故結果非負。
fn sub_magnitudes(x: &[u32], y: &[u32]) -> Vec<u32> {
    debug_assert!(
        compare_magnitude(x, y) != Ordering::Less,
        "sub_magnitudes 需要 x >= y"
    );

    let mut result = x.to_vec();
    sub_in_place(&mut result, y); // 減法與借位傳遞交給原地核心
    trim_leading_zeros(result) // 高位相消可能縮短
}

/// 原地減法：`x -= y`（big-endian，低位對齊）。
///
/// 前提：數值上 `x >= y`（呼叫端保證），故不會借位溢出頂端。
/// 供除法內圈與 `sub_magnitudes` 使用，避免每次相減都配置。
fn sub_in_place(x: &mut [u32], y: &[u32]) {
    debug_assert!(x.len() >= y.len(), "sub_in_place 需要 x.len() >= y.len()");

    let mut borrow = 0i64;
    let mut xi = x.len();

    // 先把 y 從 x 的低位端逐字減掉（兩者尾端對齊）
    for &yw in y.iter().rev() {
        xi -= 1;
        let diff = x[xi] as i64 - yw as i64 - borrow;
        x[xi] = diff as u32; // 負則回繞，等同借位
        borrow = (diff < 0) as i64; // 0 或 1
    }
    // 剩餘借位往更高位傳（xi > 0 護欄避免下溢，並讓下方 assert 給清楚訊息）
    while borrow != 0 && xi > 0 {
        xi -= 1;
        let (v, b) = x[xi].overflowing_sub(1);
        x[xi] = v;
        borrow = b as i64;
    }

    debug_assert!(borrow == 0, "sub_in_place：x < y（借位溢出頂端）");
}

/// 兩個 magnitude（big-endian、無前導零）相乘，回傳結果（無前導零）。
///
/// 乘積最多 `x.len() + y.len()` 字，先配足再 trim。
// TODO(karatsuba)：目前是 schoolbook 長乘法，複雜度 O(n²)。大數應改走 Karatsuba
// 分治（把每個運算元切成高/低兩半，三次遞迴子乘法，複雜度約 O(n^1.585)）加速；
// 小於某個門檻字數（bc-csharp 用 KaratsubaMultiplyLimit）仍維持此法以免遞迴開銷。
// 作法：新增 `KARATSUBA_THRESHOLD`，依 x/y 較短者長度決定走 schoolbook 或遞迴。
// 對應地 square_magnitude 也可加 Karatsuba squaring。
fn multiply_magnitudes(x: &[u32], y: &[u32]) -> Vec<u32> {
    if x.is_empty() || y.is_empty() {
        return Vec::new(); // 任一為零 → 0
    }
    let mut result = vec![0u32; x.len() + y.len()];

    // 對 y 的每個字（由低位到高位），把整個 x 乘上去、加進 result 對應視窗
    for i in (0..y.len()).rev() {
        let a = y[i] as u64;
        if a != 0 {
            let mut carry = 0u64;
            for j in (0..x.len()).rev() {
                let pos = i + 1 + j; // 此 y 字對齊的視窗；a·x[j]+result[pos]+carry ≤ 2^64-1
                let v = a * x[j] as u64 + result[pos] as u64 + carry;
                result[pos] = v as u32;
                carry = v >> 32;
            }
            result[i] = carry as u32; // 進位落在視窗上方一格
        }
    }

    trim_leading_zeros(result)
}

/// 平方（利用對稱性 `x[i]·x[j]` 只算一次再乘 2，約為通用乘法兩倍快）。
///
/// 回傳 `x²` 的 magnitude（big-endian、無前導零）。與 `multiply_magnitudes(x, x)`
/// 結果相同，僅乘法次數約少一半（複雜度仍為 O(n²)）。
// TODO(karatsuba)：大數平方可改 Karatsuba squaring，見 multiply_magnitudes 的 TODO。
fn square_magnitude(x: &[u32]) -> Vec<u32> {
    if x.is_empty() {
        return Vec::new();
    }
    let n = x.len();
    let mut w = vec![0u32; 2 * n];

    // 用帶號索引，方便處理「遞減到 -1」的邊界檢查
    let mut w_base: isize = (2 * n - 1) as isize;

    for i in (1..n).rev() {
        let v = x[i] as u64;

        // 對角項 x[i]²
        let mut c = v * v + w[w_base as usize] as u64;
        w[w_base as usize] = c as u32;
        c >>= 32;

        // 非對角項 2·x[i]·x[j]：算一次乘 2
        for j in (0..i).rev() {
            let prod = v * x[j] as u64;
            w_base -= 1;
            // (prod as u32) << 1 是低 32 位乘 2；prod >> 31 補回乘 2 溢出低位的部分
            c += w[w_base as usize] as u64 + (((prod as u32) << 1) as u64);
            w[w_base as usize] = c as u32;
            c = (c >> 32) + (prod >> 31);
        }

        w_base -= 1;
        c += w[w_base as usize] as u64;
        w[w_base as usize] = c as u32;

        w_base -= 1;
        if w_base >= 0 {
            w[w_base as usize] = (c >> 32) as u32;
        } else {
            debug_assert_eq!(c >> 32, 0);
        }

        w_base += i as isize;
    }

    // 最低字 x[0]²
    let mut c = x[0] as u64;
    c = c * c + w[w_base as usize] as u64;
    w[w_base as usize] = c as u32;

    w_base -= 1;
    if w_base >= 0 {
        // C# 此處為 int += 會 wrap；用 wrapping_add 對齊語義並避免 debug panic
        let idx = w_base as usize;
        w[idx] = w[idx].wrapping_add((c >> 32) as u32);
    } else {
        debug_assert_eq!(c >> 32, 0);
    }

    trim_leading_zeros(w)
}

/// 將 magnitude（big-endian、無前導零）左移 `n` 位，回傳結果（無前導零）。
///
/// 前提：`mag` 非空（移位零由呼叫端擋掉）。
fn shift_left_magnitude(mag: &[u32], n: usize) -> Vec<u32> {
    debug_assert!(!mag.is_empty(), "shift_left_magnitude 需要非空 magnitude");

    let n_ints = n >> 5; // n / 32：要往低位補幾個整字
    let n_bits = n & 0x1F; // n % 32：字內再移幾位
    let mag_len = mag.len();
    let mut new_mag: Vec<u32>;

    if n_bits == 0 {
        // 剛好整字倍數：mag 放前面，尾端補 n_ints 個零字
        new_mag = vec![0u32; mag_len + n_ints];
        new_mag[0..mag_len].copy_from_slice(mag);
    } else {
        let mut i = 0;
        let n_bits2 = 32 - n_bits;
        let high_bits = mag[0] >> n_bits2; // 最高字移出頂端的位元

        if high_bits != 0 {
            // 溢出頂端 → 需要多一個前導字
            new_mag = vec![0u32; mag_len + n_ints + 1];
            new_mag[i] = high_bits;
            i += 1;
        } else {
            new_mag = vec![0u32; mag_len + n_ints];
        }

        // 逐字左移，並把下一字的高位帶進來（跨字進位）
        let mut m = mag[0];
        for j in 0..(mag_len - 1) {
            let next = mag[j + 1];
            new_mag[i] = (m << n_bits) | (next >> n_bits2);
            i += 1;
            m = next;
        }
        // 最低字沒有下一字可帶
        new_mag[i] = mag[mag_len - 1] << n_bits;
    }

    new_mag
}

/// 將 magnitude（big-endian、無前導零）右移 `n` 位，回傳結果（無前導零）。
///
/// 前提：`mag` 非空，且 `n` 小於總位元數 `mag.len() * WORD_BITS`。
/// 「整個移光成零」的情形由呼叫端先攔掉（直接回零），不進本函式。
fn shift_right_magnitude(mag: &[u32], n: usize) -> Vec<u32> {
    let mut result = mag.to_vec();
    shift_right_in_place(&mut result, n); // 位移與跨字補位交給原地核心（前提檢查在其中）
    trim_leading_zeros(result) // 原地版高位補 0，去掉空出的前導零字即得緊湊結果
}

/// 原地右移 `n` 位（big-endian，固定長度，高位空出處填 0，不 trim）。
///
/// 供除法內圈使用。前提：`mag` 非空，且 `n < mag.len() * WORD_BITS`。
fn shift_right_in_place(mag: &mut [u32], n: usize) {
    debug_assert!(!mag.is_empty(), "shift_right_in_place 需要非空 mag");
    debug_assert!(n < mag.len() * WORD_BITS, "shift_right_in_place: n 超出總位元數");

    let n_ints = n / WORD_BITS; // 整字搬移數
    let n_bits = n % WORD_BITS; // 字內位移
    let end = mag.len() - 1; // 最低位字索引（big-endian）

    // 階段 1：整字搬移（往低位方向搬 n_ints 格），空出的高位字填 0
    if n_ints != 0 {
        for i in (n_ints..=end).rev() {
            mag[i] = mag[i - n_ints];
        }
        for w in &mut mag[..n_ints] {
            *w = 0;
        }
    }

    // 階段 2：字內右移 n_bits，補入高位鄰字掉下來的位
    if n_bits != 0 {
        let n_bits2 = WORD_BITS - n_bits;
        let mut m = mag[end];
        for i in (n_ints + 1..=end).rev() {
            let next = mag[i - 1];
            mag[i] = (m >> n_bits) | (next << n_bits2);
            m = next;
        }
        mag[n_ints] >>= n_bits; // 最高有效字沒有更高鄰字可帶入
    }
}

/// 原地右移 1 位（big-endian）。除法內圈的高頻特化版，比通用版省去 word 搬移判斷。
fn shift_right_one_in_place(mag: &mut [u32]) {
    debug_assert!(!mag.is_empty(), "shift_right_one_in_place 需要非空 mag");
    // 由高位字往低位處理：每字右移 1，補入高位鄰字掉下來的最低位。
    // 讀 mag[i-1] 時它尚未被改（處理順序在後），故不需 carry 變數。
    for i in (1..mag.len()).rev() {
        mag[i] = (mag[i] >> 1) | (mag[i - 1] << (WORD_BITS - 1));
    }
    mag[0] >>= 1; // 最高字沒有更高鄰字
}

/// 長除法（位移相減法）：回傳 `(商, 餘)` 的 magnitude（皆 big-endian、無前導零）。
///
/// `dividend`、`divisor` 皆 big-endian、無前導零。呼叫端須保證 `divisor` 非零。
fn div_magnitudes(dividend: &[u32], divisor: &[u32]) -> (Vec<u32>, Vec<u32>) {
    debug_assert!(!dividend.is_empty() && dividend[0] != 0, "div_magnitudes: 被除數須無前導零");
    debug_assert!(!divisor.is_empty() && divisor[0] != 0, "div_magnitudes: 除數須非零且無前導零");

    let mut x = dividend.to_vec(); // 可變工作副本 → 最後成為餘數
    let y = divisor; // 除數不變
    let mut x_start = 0; // x 的有效起點；相減後會往前推進

    let mut xy_cmp = compare_magnitude(&x[x_start..], y);
    let mut count: Vec<u32>;

    if xy_cmp == Ordering::Greater {
        let y_bit_length = calc_bit_length(1, y) as usize;
        let mut x_bit_length = calc_bit_length(1, &x[x_start..]) as usize;
        let mut shift = x_bit_length as isize - y_bit_length as isize;

        let mut i_count: Vec<u32>; // 目前這個 c 對應的商位（= 2^shift）
        let mut i_count_start = 0;

        let mut c: Vec<u32>; // 除數左移後的版本
        let mut c_start = 0;
        let mut c_bit_length = y_bit_length;

        if shift > 0 {
            // c = y << shift；對應商位 i_count = 1 << shift
            i_count = vec![0u32; (shift as usize / WORD_BITS) + 1];
            i_count[0] = 1u32 << (shift as usize % WORD_BITS);
            c = shift_left_magnitude(y, shift as usize);
            c_bit_length += shift as usize;
        } else {
            i_count = vec![1u32];
            c = y.to_vec();
        }

        count = vec![0u32; i_count.len()];

        loop {
            if c_bit_length < x_bit_length
                || compare_magnitude(&x[x_start..], &c[c_start..]) != Ordering::Less
            {
                // x >= c：x -= c，商累加 i_count
                sub_in_place(&mut x[x_start..], &c[c_start..]);
                add_in_place(&mut count, &i_count);

                // 跳過相減後 x 新產生的前導零字
                while x[x_start] == 0 {
                    x_start += 1;
                    if x_start == x.len() {
                        // 餘數為 0
                        return (trim_leading_zeros(count), trim_leading_zeros(x));
                    }
                }

                x_bit_length = WORD_BITS * (x.len() - x_start - 1) + bit_len(x[x_start]) as usize;

                if x_bit_length <= y_bit_length {
                    if x_bit_length < y_bit_length {
                        // x < y：餘數就是現在的 x
                        return (trim_leading_zeros(count), trim_leading_zeros(x));
                    }
                    xy_cmp = compare_magnitude(&x[x_start..], y);
                    if xy_cmp != Ordering::Greater {
                        break; // x <= y
                    }
                }
            }

            // 把 c（連同 i_count）右移，逼近 x 的位長
            shift = c_bit_length as isize - x_bit_length as isize;
            // NB: c 只剩 1 bit 的情形無害
            if shift == 1 {
                let first_c = c[c_start] >> 1;
                let first_x = x[x_start];
                if first_c > first_x {
                    shift += 1;
                }
            }
            if shift < 2 {
                shift_right_one_in_place(&mut c[c_start..]);
                c_bit_length -= 1;
                shift_right_one_in_place(&mut i_count[i_count_start..]);
            } else {
                shift_right_in_place(&mut c[c_start..], shift as usize);
                c_bit_length -= shift as usize;
                shift_right_in_place(&mut i_count[i_count_start..], shift as usize);
            }

            // 右移後高位可能空出零字，推進起點
            while c[c_start] == 0 {
                c_start += 1;
            }
            while i_count[i_count_start] == 0 {
                i_count_start += 1;
            }
        }
    } else {
        count = vec![0u32]; // x < y（商 0）或 x == y（下面補 1）
    }

    if xy_cmp == Ordering::Equal {
        // x 恰等於 y：商 +1，餘數歸零
        add_in_place(&mut count, &[1]);
        for w in &mut x[x_start..] {
            *w = 0;
        }
    }

    (trim_leading_zeros(count), trim_leading_zeros(x))
}

/// 擴展歐幾里得：回傳 `(gcd(a, b), x)`，其中 `x` 滿足 `a·x ≡ gcd (mod b)`。
///
/// 前提：`b` 為正、`a` 非負（呼叫端若有負值，先用 `rem_euclid` 約簡）。
/// 一路輾轉相除（`div_rem`）約簡 `(u3, v3)`，同時把 `a` 的係數 `(u1, v1)` 帶著走；
/// 維持不變量 `u3 ≡ a·u1 (mod b)`，收斂時 `u3 = gcd`、`u1 = x`。
fn extended_gcd(a: &BigInteger, b: &BigInteger) -> (BigInteger, BigInteger) {
    let mut u1 = BigInteger::from_u32(1);
    let mut v1 = BigInteger::from_u32(0);
    let mut u3 = a.clone();
    let mut v3 = b.clone();

    if v3.sign() > 0 {
        loop {
            let (q, r) = u3.div_rem(&v3);
            u3 = v3;
            v3 = r;

            let old_u1 = u1;
            u1 = v1.clone(); // v1 稍後 `&v1 * &q` 還要用，不能 move → clone
            if v3.sign() <= 0 {
                break;
            }
            v1 = &old_u1 - &(&v1 * &q); // v1 = old_u1 - v1 * q
        }
    }
    (u3, u1) // (gcd, 係數 x)
}

/// 檢查 magnitude（big-endian）最低 `n` 位是否有任何設定位元。
///
/// 供負數右移的 floor 修正：被移出的低位若非零，代表截斷有損失，需向下多退一。
/// 前提：`n` 小於總位元數（呼叫端已保證），故 `word_shift <= len - 1`。
fn any_low_bits_set(mag: &[u32], n: usize) -> bool {
    let word_shift = n / WORD_BITS; // 低位端整字數
    let bit_shift = n % WORD_BITS; // 再上一字要看的低位位數
    let len = mag.len();

    // 最低 word_shift 個整字，只要有一個非零就成立
    if mag[len - word_shift..].iter().any(|&w| w != 0) {
        return true;
    }
    // 再上一字的低 bit_shift 位（bit_shift == 0 時無此殘位）
    if bit_shift != 0 && mag[len - word_shift - 1] & ((1u32 << bit_shift) - 1) != 0 {
        return true;
    }
    false
}

/// 把 `x` 展成 `len` 個字的兩補數表示（big-endian、符號延伸），供位元運算逐字處理。
///
/// - 零 / 正數：magnitude 右對齊，上方補 `0`。
/// - 負數：`-m` 的兩補數 = `~(m - 1)`，故取 `(x + 1)` 的 magnitude（值 = `m - 1`）右對齊後
///   **整體反相**；連上方 padding 的 `0` 也翻成 `0xFFFF_FFFF`，即符號延伸（無限個 1）。
///
/// 前提：`len` 至少容得下該來源 magnitude 的字數（呼叫端以兩運算元取 max 保證）。
fn to_twos_complement_words(x: &BigInteger, len: usize) -> Vec<u32> {
    let mut words = vec![0u32; len];
    if x.sign == 0 {
        return words; // 0 → 全 0
    }

    let negative = x.sign < 0;
    // 負數要讓 (x + 1) 這個暫時值活到 copy 完；用「延後初始化」的 let 延長其壽命，免 clone。
    let neg_tmp;
    let src: &[u32] = if negative {
        neg_tmp = x + &BigInteger::from_u32(1);
        &neg_tmp.magnitude
    } else {
        &x.magnitude
    };

    words[len - src.len()..].copy_from_slice(src); // big-endian 右對齊
    if negative {
        for w in &mut words {
            *w = !*w; // 整體反相 → 兩補數（含上方符號延伸）
        }
    }
    words
}

/// 位元運算共用骨架：兩運算元攤成同長度兩補數字，逐字套 `op`，`result_neg` 決定結果符號。
///
/// 長度取兩者 magnitude 字數的 max 已足夠：多出的高位字都是符號延伸，收尾 trim 掉；
/// 負結果先在迴圈裡整體反相存成 `|result| - 1`，最後 `!` 一次轉回負（進位長大由 Not 吸收）。
///
/// 前提：`a`、`b` 皆非零（零的捷徑由各運算子先處理）。
fn bitwise(a: &BigInteger, b: &BigInteger, result_neg: bool, op: impl Fn(u32, u32) -> u32) -> BigInteger {
    let len = a.magnitude.len().max(b.magnitude.len());
    let aw = to_twos_complement_words(a, len);
    let bw = to_twos_complement_words(b, len);

    let mut result = vec![0u32; len];
    for i in 0..len {
        let mut w = op(aw[i], bw[i]);
        if result_neg {
            w = !w; // 負結果：先存 |result| - 1 的字
        }
        result[i] = w;
    }

    let result = BigInteger::from_checked_magnitude(1, result); // 去前導零 + 全零歸零
    if result_neg { !&result } else { result }
}

/// 計算負數的 bitCount，等於 `popcount(magnitude - 1)`。
///
/// `magnitude` 為 big-endian、非空（負數必非零）。減 1 從最低位（尾端）借位。
fn bit_count_negative(magnitude: &[u32]) -> u32 {
    let mut borrow = true; // 減 1：一開始就欠一個借位
    let mut count = 0;
    for &w in magnitude.iter().rev() {
        let v = if borrow {
            let (r, b) = w.overflowing_sub(1);
            borrow = b; // w == 0 時借位繼續往高位傳
            r
        } else {
            w
        };
        count += v.count_ones();
    }
    count
}

/// 對位元組陣列原地取兩補數：`bytes = ~bytes + 1`（同寬度，進位由低位端往高位傳）。
fn twos_complement_in_place(bytes: &mut [u8]) {
    let mut carry = true; // 加 1：一開始就有一個進位待處理
    for b in bytes.iter_mut().rev() {
        *b = !*b;
        if carry {
            let (v, c) = b.overflowing_add(1);
            *b = v;
            carry = c;
        }
    }
}

fn make_magnitude_be(buffer: &[u8]) -> Vec<u32> {
    // 去除前導零位元組；全零（或空）緩衝區會得到空切片
    let start = buffer.iter().position(|&b| b != 0).unwrap_or(buffer.len());

    buffer[start..]
        .rchunks(size_of::<u32>()) // 從低位端每 4 位元組切一塊
        .rev() // 反轉，讓最高位的字排在前面
        .map(|chunk| chunk.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32))
        .collect()
}

/// 將 big-endian 兩補數負數位元組還原成其絕對值的 magnitude。
///
/// 前提：`buffer` 代表負數（最高位元組的最高位為 1）。
fn make_magnitude_be_negative(buffer: &[u8]) -> Vec<u32> {
    // 兩補數轉絕對值：全部反相，再從最低位 (尾端) 加 1
    let mut inverse: Vec<u8> = buffer.iter().map(|&b| !b).collect();
    for b in inverse.iter_mut().rev() {
        if *b == 0xFF {
            *b = 0; // 0xFF + 1 = 0x00，進位繼續往高位
        } else {
            *b += 1; // 沒有進位，結束
            break;
        }
    }
    // 反相後即為絕對值的 BE 位元組，交給既有 helper 去零、打包
    make_magnitude_be(&inverse)
}

fn make_magnitude_le(buffer: &[u8]) -> Vec<u32> {
    // little-endian：最高位在尾端，所以去除「尾端」的零位元組
    let end = buffer.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);

    buffer[..end]
        .chunks(size_of::<u32>()) // 從低位端每 4 位元組切一塊（低位字先出）
        .rev() // 反轉，讓最高位的字排在前面
        .map(|chunk| chunk.iter().rev().fold(0u32, |acc, &b| (acc << 8) | b as u32))
        .collect()
}

/// 將 little-endian 兩補數負數位元組還原成其絕對值的 magnitude。
///
/// 前提：`buffer` 代表負數（最高位元組的最高位為 1；最高位元組在尾端）。
fn make_magnitude_le_negative(buffer: &[u8]) -> Vec<u32> {
    // 兩補數轉絕對值：全部反相，再從最低位 (前端) 加 1
    let mut inverse: Vec<u8> = buffer.iter().map(|&b| !b).collect();
    for b in inverse.iter_mut() {
        if *b == 0xFF {
            *b = 0; // 0xFF + 1 = 0x00，進位繼續往高位
        } else {
            *b += 1; // 沒有進位，結束
            break;
        }
    }
    // 反相後即為絕對值的 LE 位元組，交給既有 helper 去零、打包
    make_magnitude_le(&inverse)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u32_zero() {
        let n = BigInteger::from_u32(0);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn sign_reports_all_three_states() {
        assert_eq!(BigInteger::from_i32(-42).sign(), -1);
        assert_eq!(BigInteger::from_i32(0).sign(), 0);
        assert_eq!(BigInteger::from_i32(42).sign(), 1);
    }

    #[test]
    fn is_zero_matches_sign() {
        assert!(BigInteger::from_i32(0).is_zero());
        assert!(!BigInteger::from_i32(1).is_zero());
        assert!(!BigInteger::from_i32(-1).is_zero());
        // 空位元組與全零位元組都應是零
        assert!(BigInteger::from_bytes_be(&[]).is_zero());
        assert!(BigInteger::from_bytes_be(&[0, 0, 0]).is_zero());
    }

    #[test]
    fn bit_length_zero() {
        assert_eq!(BigInteger::from_u32(0).bit_length(), 0);
    }

    #[test]
    fn bit_length_positive() {
        assert_eq!(BigInteger::from_u32(1).bit_length(), 1); // 0b1
        assert_eq!(BigInteger::from_u32(5).bit_length(), 3); // 0b101
        assert_eq!(BigInteger::from_u32(8).bit_length(), 4); // 0b1000
        assert_eq!(BigInteger::from_u32(255).bit_length(), 8);
        assert_eq!(BigInteger::from_u32(256).bit_length(), 9);
    }

    #[test]
    fn bit_length_negative_non_power_of_two() {
        // 非 2 次方的負數，位元長度與正數相同
        assert_eq!(BigInteger::from_i32(-5).bit_length(), 3);
        assert_eq!(BigInteger::from_i32(-7).bit_length(), 3);
    }

    #[test]
    fn bit_length_negative_power_of_two_is_one_less() {
        // 負的 2 次方少 1 位：-8 為 3（+8 為 4）
        assert_eq!(BigInteger::from_i32(-8).bit_length(), 3);
        assert_eq!(BigInteger::from_i32(-1).bit_length(), 0); // -1 = -2^0
        assert_eq!(BigInteger::from_i32(-256).bit_length(), 8);
    }

    #[test]
    fn bit_length_multi_word() {
        // 2^32：magnitude [1, 0]，位元長度 33；負的則為 32
        assert_eq!(BigInteger::from_u64(1 << 32).bit_length(), 33);
        assert_eq!(BigInteger::from_i64(-(1 << 32)).bit_length(), 32);
        // u64::MAX 佔滿 64 位
        assert_eq!(BigInteger::from_u64(u64::MAX).bit_length(), 64);
    }

    #[test]
    fn bit_length_is_stable() {
        // 每次重算，結果一致
        let n = BigInteger::from_u32(5);
        assert_eq!(n.bit_length(), 3);
        assert_eq!(n.bit_length(), 3);
    }

    #[test]
    fn bit_count_zero() {
        assert_eq!(BigInteger::from_u32(0).bit_count(), 0);
    }

    #[test]
    fn bit_count_positive() {
        assert_eq!(BigInteger::from_u32(0b101).bit_count(), 2);
        assert_eq!(BigInteger::from_u32(0b111).bit_count(), 3);
        assert_eq!(BigInteger::from_u32(0xFF).bit_count(), 8);
        assert_eq!(BigInteger::from_u32(u32::MAX).bit_count(), 32);
    }

    #[test]
    fn bit_count_positive_multi_word() {
        // u64::MAX 全為 1，共 64 個
        assert_eq!(BigInteger::from_u64(u64::MAX).bit_count(), 64);
    }

    #[test]
    fn bit_count_negative() {
        // 負數：popcount(|n| - 1)
        assert_eq!(BigInteger::from_i32(-1).bit_count(), 0); // |−1|−1 = 0
        assert_eq!(BigInteger::from_i32(-2).bit_count(), 1); // 1 = 0b1
        assert_eq!(BigInteger::from_i32(-8).bit_count(), 3); // 7 = 0b111
    }

    #[test]
    fn bit_count_negative_multi_word_borrow() {
        // -(2^32)：|n|-1 = 2^32-1 = 0xFFFF_FFFF，借位跨字，共 32 個 1
        assert_eq!(BigInteger::from_i64(-(1 << 32)).bit_count(), 32);
    }

    #[test]
    fn cmp_same_sign_positive() {
        assert_eq!(BigInteger::from_i32(5).cmp(&BigInteger::from_i32(3)), Ordering::Greater);
        assert_eq!(BigInteger::from_i32(3).cmp(&BigInteger::from_i32(5)), Ordering::Less);
        assert_eq!(BigInteger::from_i32(5).cmp(&BigInteger::from_i32(5)), Ordering::Equal);
    }

    #[test]
    fn cmp_same_sign_negative_is_flipped() {
        // 同負號：絕對值大者反而小
        assert_eq!(BigInteger::from_i32(-5).cmp(&BigInteger::from_i32(-3)), Ordering::Less);
        assert_eq!(BigInteger::from_i32(-3).cmp(&BigInteger::from_i32(-5)), Ordering::Greater);
    }

    #[test]
    fn cmp_different_signs() {
        assert_eq!(BigInteger::from_i32(5).cmp(&BigInteger::from_i32(-8)), Ordering::Greater);
        assert_eq!(BigInteger::from_i32(-8).cmp(&BigInteger::from_i32(5)), Ordering::Less);
    }

    #[test]
    fn cmp_with_zero() {
        assert_eq!(BigInteger::from_i32(0).cmp(&BigInteger::from_i32(-3)), Ordering::Greater);
        assert_eq!(BigInteger::from_i32(0).cmp(&BigInteger::from_i32(5)), Ordering::Less);
        assert_eq!(BigInteger::from_i32(0).cmp(&BigInteger::from_i32(0)), Ordering::Equal);
    }

    #[test]
    fn cmp_by_word_count() {
        // 字數多者絕對值大（依賴無前導零不變量）
        let big = BigInteger::from_u64(1 << 32); // magnitude [1, 0]，2 字
        let small = BigInteger::from_u32(u32::MAX); // magnitude [0xFFFFFFFF]，1 字
        assert_eq!(big.cmp(&small), Ordering::Greater);
    }

    #[test]
    fn cmp_operators_and_min_max() {
        // 實作 Ord 後，運算子與 min/max/sort 自動可用
        let a = BigInteger::from_i32(-10);
        let b = BigInteger::from_i32(7);
        assert!(a < b);
        assert!(b >= a);
        assert_eq!(a.clone().min(b.clone()), a);
        assert_eq!(a.clone().max(b.clone()), b);

        let mut v = vec![
            BigInteger::from_i32(3),
            BigInteger::from_i32(-5),
            BigInteger::from_i32(0),
            BigInteger::from_i32(1),
        ];
        v.sort();
        // 排序後應為 -5, 0, 1, 3（由小到大）
        let expected = [-5, 0, 1, 3].map(BigInteger::from_i32);
        assert_eq!(v, expected);
    }

    #[test]
    fn eq_with_i32() {
        assert_eq!(BigInteger::from_i32(42), 42);
        assert_eq!(BigInteger::from_i32(-42), -42);
        assert_eq!(BigInteger::from_i32(0), 0);
        assert_ne!(BigInteger::from_i32(42), 43);
        // 超出 i32 範圍的大數不等於任何 i32
        assert_ne!(BigInteger::from_u64(1 << 40), 0);
    }

    #[test]
    fn partial_ord_with_i32() {
        let n = BigInteger::from_i32(100);
        assert!(n > 5);
        assert!(n >= 100);
        assert!(n < 1000);
        assert!(BigInteger::from_i32(-1) < 0);
        assert!(BigInteger::from_i32(0) >= 0);
        // 兩端點與大數
        assert!(BigInteger::from_i64(1 << 40) > i32::MAX);
        assert!(BigInteger::from_i64(-(1 << 40)) < i32::MIN);
    }

    #[test]
    fn cmp_with_unsigned_types() {
        // u8 / u32 / u64 / u128，含超過單字與 u128 極值
        assert_eq!(BigInteger::from_u32(200), 200u8);
        assert!(BigInteger::from_u64(1 << 40) > u32::MAX);
        assert_eq!(BigInteger::from_u64(u64::MAX), u64::MAX);
        assert!(BigInteger::from_u64(u64::MAX) < (u64::MAX as u128 + 1));

        // u128::MAX = 2^128 - 1（4 字全 1）→ 相等；2^128 → 更大
        let max_u128 = BigInteger::from_u32_be_unsigned(&[u32::MAX; 4]);
        assert_eq!(max_u128, u128::MAX);
        assert!((&max_u128 + &BigInteger::from_u32(1)) > u128::MAX);
        // 負數恆小於任何無號數
        assert!(BigInteger::from_i32(-1) < 0u128);
    }

    #[test]
    fn cmp_with_wide_signed_types() {
        // i64 / i128，含 MIN 端點（unsigned_abs 不溢位）
        assert_eq!(BigInteger::from_i64(i64::MIN), i64::MIN);
        assert_eq!(BigInteger::from_i128(i128::MIN), i128::MIN);
        assert!(BigInteger::from_i128(i128::MIN) < i128::MIN + 1);
        assert!(BigInteger::from_i64(-(1 << 40)) < 0i64);
        assert!(BigInteger::from_i64(1 << 40) > 1_000_000i64);
    }

    #[test]
    fn neg_flips_sign_keeps_magnitude() {
        let n = -BigInteger::from_i32(5);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);

        let p = -BigInteger::from_i32(-5);
        assert_eq!(p.sign, 1);
        assert_eq!(p.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn neg_zero_is_zero() {
        let z = -BigInteger::from_i32(0);
        assert_eq!(z.sign, 0);
        assert!(z.magnitude.is_empty());
    }

    #[test]
    fn neg_is_involution() {
        // -(-a) == a
        let a = BigInteger::from_i64(-123456789);
        assert_eq!(-(-a.clone()), a);
    }

    #[test]
    fn neg_bit_length_reflects_sign() {
        // 8 的 bit_length 為 4，取負後為 3（負的 2 次方少 1）
        let a = BigInteger::from_i32(8);
        assert_eq!(a.bit_length(), 4);
        let b = -a; // a 的 magnitude buffer 搬進 b
        assert_eq!(b.bit_length(), 3);
    }

    #[test]
    fn abs_of_negative_and_positive() {
        assert_eq!(BigInteger::from_i32(-5).abs(), BigInteger::from_i32(5));
        assert_eq!(BigInteger::from_i32(5).abs(), BigInteger::from_i32(5));
    }

    #[test]
    fn abs_zero_is_zero() {
        let z = BigInteger::from_i32(0).abs();
        assert_eq!(z.sign, 0);
        assert!(z.magnitude.is_empty());
    }

    #[test]
    fn abs_bit_length_reflects_sign() {
        // -8 的 bit_length 為 3；取絕對值後為 8，bit_length 為 4
        let a = BigInteger::from_i32(-8);
        assert_eq!(a.bit_length(), 3);
        assert_eq!(a.abs().bit_length(), 4);
    }

    #[test]
    fn abs_is_idempotent() {
        let a = BigInteger::from_i64(-123456789);
        assert_eq!(a.clone().abs().abs(), a.abs());
    }

    #[test]
    fn not_basic_identity() {
        // !x = -(x + 1)
        assert_eq!(!&BigInteger::from_i32(0), BigInteger::from_i32(-1)); // ~0 = -1
        assert_eq!(!&BigInteger::from_i32(5), BigInteger::from_i32(-6)); // ~5 = -6
        assert_eq!(!&BigInteger::from_i32(-1), BigInteger::from_i32(0)); // ~-1 = 0
        assert_eq!(!&BigInteger::from_i32(-8), BigInteger::from_i32(7)); // ~-8 = 7
    }

    #[test]
    fn not_is_involution() {
        // !!x == x
        let a = BigInteger::from_i64(-123456789);
        assert_eq!(!&!&a, a);
    }

    #[test]
    fn not_matches_i128_reference() {
        // 拿原生 i128 的位元 NOT 當獨立參照
        let vals = [0i64, 1, -1, 5, -5, 255, -256, 0xFFFF_FFFF, -(0xFFFF_FFFFi64), 1 << 40, -(1 << 40)];
        for &a in &vals {
            let got = !&BigInteger::from_i64(a);
            let want = BigInteger::from_i128(!(a as i128));
            assert_eq!(got, want, "!{a}");
        }
    }

    #[test]
    fn twos_complement_words_layout() {
        // 正數：magnitude 右對齊、上方補 0
        assert_eq!(to_twos_complement_words(&BigInteger::from_u32(5), 3), vec![0, 0, 5]);
        // 零：全 0
        assert_eq!(to_twos_complement_words(&BigInteger::from_u32(0), 2), vec![0, 0]);
        // -1：無限個 1 → 每字皆 0xFFFF_FFFF
        assert_eq!(
            to_twos_complement_words(&BigInteger::from_i32(-1), 2),
            vec![0xFFFF_FFFF, 0xFFFF_FFFF]
        );
        // -2 = ...1110 → 低字 0xFFFF_FFFE
        assert_eq!(to_twos_complement_words(&BigInteger::from_i32(-2), 1), vec![0xFFFF_FFFE]);
        // -256 → 低字 0xFFFF_FF00，上方字符號延伸為 0xFFFF_FFFF
        assert_eq!(
            to_twos_complement_words(&BigInteger::from_i32(-256), 2),
            vec![0xFFFF_FFFF, 0xFFFF_FF00]
        );
    }

    #[test]
    fn twos_complement_words_matches_i128_reference() {
        // 拿原生 i64→i128 的兩補數位元當對照（取低 2 個 32-bit 字）
        let vals = [0i64, 1, -1, 5, -5, 255, -256, 0xFFFF_FFFF, -(0xFFFF_FFFFi64)];
        for &a in &vals {
            let words = to_twos_complement_words(&BigInteger::from_i64(a), 2);
            let bits = a as u64; // 兩補數位元模式
            assert_eq!(words, vec![(bits >> 32) as u32, bits as u32], "value {a}");
        }
    }

    #[test]
    fn bitand_basic() {
        // 正 & 正
        assert_eq!(&BigInteger::from_u32(12) & &BigInteger::from_u32(10), BigInteger::from_u32(8));
        // 負 & 正（-8 = ...11111000）
        assert_eq!(&BigInteger::from_i32(-8) & &BigInteger::from_i32(6), BigInteger::from_i32(0));
        assert_eq!(&BigInteger::from_i32(-8) & &BigInteger::from_i32(12), BigInteger::from_i32(8));
        // 負 & 負 → 負
        assert_eq!(&BigInteger::from_i32(-1) & &BigInteger::from_i32(-1), BigInteger::from_i32(-1));
        assert_eq!(&BigInteger::from_i32(-2) & &BigInteger::from_i32(-3), BigInteger::from_i32(-4));
        // 任一為 0
        assert_eq!(&BigInteger::from_u32(0) & &BigInteger::from_i32(-5), BigInteger::from_u32(0));
    }

    #[test]
    fn bitor_basic() {
        assert_eq!(&BigInteger::from_u32(12) | &BigInteger::from_u32(10), BigInteger::from_u32(14));
        assert_eq!(&BigInteger::from_i32(-8) | &BigInteger::from_i32(6), BigInteger::from_i32(-2));
        assert_eq!(&BigInteger::from_i32(-1) | &BigInteger::from_i32(-1), BigInteger::from_i32(-1));
        // 一方為 0 → 另一方
        assert_eq!(&BigInteger::from_u32(0) | &BigInteger::from_i32(-5), BigInteger::from_i32(-5));
        assert_eq!(&BigInteger::from_i32(7) | &BigInteger::from_u32(0), BigInteger::from_i32(7));
    }

    #[test]
    fn bitxor_basic() {
        assert_eq!(&BigInteger::from_u32(5) ^ &BigInteger::from_u32(3), BigInteger::from_u32(6));
        assert_eq!(&BigInteger::from_i32(-1) ^ &BigInteger::from_i32(5), BigInteger::from_i32(-6));
        assert_eq!(&BigInteger::from_i32(-1) ^ &BigInteger::from_i32(-1), BigInteger::from_i32(0));
        // 一方為 0 → 另一方
        assert_eq!(&BigInteger::from_u32(0) ^ &BigInteger::from_i32(-5), BigInteger::from_i32(-5));
        assert_eq!(&BigInteger::from_i32(7) ^ &BigInteger::from_u32(0), BigInteger::from_i32(7));
    }

    #[test]
    fn bitwise_matches_i128_reference() {
        // 拿原生 i128 的 & / | / ^ 當獨立參照，涵蓋各種符號與跨字組合
        let vals = [
            0i64, 1, -1, 5, -5, 12, -12, 255, -256,
            0xFFFF_FFFF, -(0xFFFF_FFFFi64), 1 << 40, -(1 << 40),
        ];
        for &a in &vals {
            for &b in &vals {
                let (x, y) = (BigInteger::from_i64(a), BigInteger::from_i64(b));
                assert_eq!(&x & &y, BigInteger::from_i128((a as i128) & (b as i128)), "{a} & {b}");
                assert_eq!(&x | &y, BigInteger::from_i128((a as i128) | (b as i128)), "{a} | {b}");
                assert_eq!(&x ^ &y, BigInteger::from_i128((a as i128) ^ (b as i128)), "{a} ^ {b}");
            }
        }
    }

    #[test]
    fn test_bit_positive() {
        let n = BigInteger::from_u32(0b1010);
        assert!(!n.test_bit(0));
        assert!(n.test_bit(1));
        assert!(!n.test_bit(2));
        assert!(n.test_bit(3));
        assert!(!n.test_bit(4)); // 超出最高設定位
        assert!(!n.test_bit(1000));
    }

    #[test]
    fn test_bit_negative() {
        // -1 = ...1111，任意位皆 1
        let neg1 = BigInteger::from_i32(-1);
        assert!(neg1.test_bit(0));
        assert!(neg1.test_bit(31));
        assert!(neg1.test_bit(1000));
        // -2 = ...1110
        let neg2 = BigInteger::from_i32(-2);
        assert!(!neg2.test_bit(0));
        assert!(neg2.test_bit(1));
        assert!(neg2.test_bit(1000));
    }

    #[test]
    fn test_bit_matches_i128_reference() {
        // 拿原生 i128 的算術右移取位當獨立參照（負數 >> 會符號延伸，正好對應兩補數）
        let vals = [0i64, 1, -1, 5, -5, 255, -256, 0xFFFF_FFFF, -(0xFFFF_FFFFi64), 1 << 40, -(1 << 40)];
        for &a in &vals {
            for n in 0..96u32 {
                let got = BigInteger::from_i64(a).test_bit(n);
                let want = (((a as i128) >> n) & 1) == 1;
                assert_eq!(got, want, "test_bit({a}, {n})");
            }
        }
    }

    #[test]
    fn set_clear_flip_bit_basic() {
        let five = BigInteger::from_u32(0b101);
        assert_eq!(five.set_bit(1), BigInteger::from_u32(0b111)); // 5 | 2 = 7
        assert_eq!(five.set_bit(0), BigInteger::from_u32(0b101)); // 已是 1，不變
        assert_eq!(five.clear_bit(0), BigInteger::from_u32(0b100)); // 5 & ~1 = 4
        assert_eq!(five.clear_bit(1), BigInteger::from_u32(0b101)); // 已是 0，不變
        assert_eq!(five.flip_bit(2), BigInteger::from_u32(0b001)); // 5 ^ 4 = 1
        assert_eq!(five.set_bit(10), BigInteger::from_u32(0b100_0000_0101)); // 跨到高位
        // 負數：-1 = ...1111，清第 0 位 → -2
        assert_eq!(BigInteger::from_i32(-1).clear_bit(0), BigInteger::from_i32(-2));
    }

    #[test]
    fn set_clear_flip_bit_matches_i128_reference() {
        // 拿原生 i128 的 |、& ~、^ 當獨立參照
        let vals = [0i64, 1, -1, 5, -5, 255, -256, 0xFFFF_FFFF, -(0xFFFF_FFFFi64)];
        for &a in &vals {
            for n in 0..70u32 {
                let x = BigInteger::from_i64(a);
                let bit = 1i128 << n;
                assert_eq!(x.set_bit(n), BigInteger::from_i128((a as i128) | bit), "set_bit({a},{n})");
                assert_eq!(x.clear_bit(n), BigInteger::from_i128((a as i128) & !bit), "clear_bit({a},{n})");
                assert_eq!(x.flip_bit(n), BigInteger::from_i128((a as i128) ^ bit), "flip_bit({a},{n})");
            }
        }
    }

    #[test]
    fn get_lowest_set_bit_basic() {
        assert_eq!(BigInteger::from_u32(0).get_lowest_set_bit(), None);
        assert_eq!(BigInteger::from_u32(1).get_lowest_set_bit(), Some(0));
        assert_eq!(BigInteger::from_u32(0b1100).get_lowest_set_bit(), Some(2));
        assert_eq!(BigInteger::from_u32(8).get_lowest_set_bit(), Some(3));
        // 跨零字：2^40 magnitude = [256, 0]，最低設定位在 40
        assert_eq!(BigInteger::from_u64(1 << 40).get_lowest_set_bit(), Some(40));
        // 整字邊界：2^32
        assert_eq!(BigInteger::from_u64(1 << 32).get_lowest_set_bit(), Some(32));
        // 負數與絕對值相同
        assert_eq!(BigInteger::from_i32(-12).get_lowest_set_bit(), Some(2));
        assert_eq!(BigInteger::from_i32(-1).get_lowest_set_bit(), Some(0));
    }

    #[test]
    fn get_lowest_set_bit_matches_trailing_zeros() {
        // 對照原生 u64::trailing_zeros（非零值）
        let vals: [u64; 7] = [1, 2, 0b1100, 255, 256, 1 << 40, u64::MAX];
        for &a in &vals {
            let got = BigInteger::from_u64(a).get_lowest_set_bit();
            assert_eq!(got, Some(a.trailing_zeros()), "value {a}");
        }
    }

    #[test]
    fn add_in_place_basic() {
        // x += y，低位對齊；x 須預留進位空間
        let mut x = vec![0, 5];
        add_in_place(&mut x, &[3]);
        assert_eq!(x, vec![0, 8]);

        // 跨字進位由預留的前導字吸收
        let mut x = vec![0, u32::MAX];
        add_in_place(&mut x, &[1]);
        assert_eq!(x, vec![1, 0]);

        // 進位鏈：0xFFFF_FFFF_FFFF_FFFF + 1
        let mut x = vec![0, u32::MAX, u32::MAX];
        add_in_place(&mut x, &[1]);
        assert_eq!(x, vec![1, 0, 0]);

        // 等長相加
        let mut x = vec![0, 0x1000_0000];
        add_in_place(&mut x, &[0, 0x2000_0000]);
        assert_eq!(x, vec![0, 0x3000_0000]);
    }

    #[test]
    fn add_magnitudes_simple() {
        assert_eq!(add_magnitudes(&[5], &[3]), vec![8]);
    }

    #[test]
    fn add_magnitudes_carry_grows_word() {
        // 0xFFFFFFFF + 1 = 0x1_0000_0000
        assert_eq!(add_magnitudes(&[u32::MAX], &[1]), vec![1, 0]);
    }

    #[test]
    fn add_magnitudes_carry_chain() {
        // (2^64 - 1) + 1 = 2^64
        assert_eq!(add_magnitudes(&[u32::MAX, u32::MAX], &[1]), vec![1, 0, 0]);
    }

    #[test]
    fn add_magnitudes_different_lengths() {
        // 2^32 + 5 = 0x1_0000_0005
        assert_eq!(add_magnitudes(&[1, 0], &[5]), vec![1, 5]);
    }

    #[test]
    fn add_magnitudes_with_empty_is_identity() {
        assert_eq!(add_magnitudes(&[5], &[]), vec![5]);
        assert_eq!(add_magnitudes(&[], &[5]), vec![5]);
        assert_eq!(add_magnitudes(&[], &[]), Vec::<u32>::new());
    }

    #[test]
    fn add_magnitudes_is_commutative() {
        let a = [0x1234_5678, 0x9ABC_DEF0];
        let b = [0xFFFF_FFFF];
        assert_eq!(add_magnitudes(&a, &b), add_magnitudes(&b, &a));
    }

    #[test]
    fn sub_in_place_basic() {
        // x -= y，低位對齊；前提 x >= y
        let mut x = vec![8];
        sub_in_place(&mut x, &[3]);
        assert_eq!(x, vec![5]);

        // 跨字借位：2^32 - 1
        let mut x = vec![1, 0];
        sub_in_place(&mut x, &[1]);
        assert_eq!(x, vec![0, u32::MAX]);

        // 借位鏈：2^64 - 1
        let mut x = vec![1, 0, 0];
        sub_in_place(&mut x, &[1]);
        assert_eq!(x, vec![0, u32::MAX, u32::MAX]);

        // 相等 → 全 0（不 trim，原地保留長度）
        let mut x = vec![5];
        sub_in_place(&mut x, &[5]);
        assert_eq!(x, vec![0]);
    }

    #[test]
    fn sub_magnitudes_simple() {
        assert_eq!(sub_magnitudes(&[8], &[3]), vec![5]);
    }

    #[test]
    fn sub_magnitudes_borrow_across_word() {
        // 2^32 - 1 = 0xFFFF_FFFF
        assert_eq!(sub_magnitudes(&[1, 0], &[1]), vec![u32::MAX]);
    }

    #[test]
    fn sub_magnitudes_borrow_chain() {
        // 2^64 - 1 = 0xFFFF_FFFF_FFFF_FFFF
        assert_eq!(sub_magnitudes(&[1, 0, 0], &[1]), vec![u32::MAX, u32::MAX]);
    }

    #[test]
    fn sub_magnitudes_equal_is_zero() {
        assert_eq!(sub_magnitudes(&[5], &[5]), Vec::<u32>::new());
    }

    #[test]
    fn sub_magnitudes_shrinks_result() {
        // (2^32 + 5) - (2^32 + 3) = 2；高位相消，結果縮成一字
        assert_eq!(sub_magnitudes(&[1, 5], &[1, 3]), vec![2]);
    }

    #[test]
    fn sub_magnitudes_with_empty_is_identity() {
        assert_eq!(sub_magnitudes(&[7], &[]), vec![7]);
    }

    #[test]
    fn sub_magnitudes_inverts_add() {
        // (a + b) - b == a
        let a = [0x1234_5678, 0x9ABC_DEF0];
        let b = [0xFEDC_BA98];
        let sum = add_magnitudes(&a, &b);
        assert_eq!(sub_magnitudes(&sum, &b), a.to_vec());
    }

    #[test]
    fn multiply_magnitudes_simple() {
        assert_eq!(multiply_magnitudes(&[5], &[3]), vec![15]);
    }

    #[test]
    fn multiply_magnitudes_with_zero() {
        assert_eq!(multiply_magnitudes(&[5], &[]), Vec::<u32>::new());
        assert_eq!(multiply_magnitudes(&[], &[5]), Vec::<u32>::new());
    }

    #[test]
    fn multiply_magnitudes_grows_to_two_words() {
        // 0x1_0000_0000 = 2^32：0x10000 * 0x10000
        assert_eq!(multiply_magnitudes(&[0x1_0000], &[0x1_0000]), vec![1, 0]);
    }

    #[test]
    fn multiply_magnitudes_max_words() {
        // (2^32 - 1)^2 = 0xFFFFFFFE_00000001
        assert_eq!(multiply_magnitudes(&[u32::MAX], &[u32::MAX]), vec![0xFFFF_FFFE, 0x0000_0001]);
    }

    #[test]
    fn multiply_magnitudes_matches_u64_reference() {
        // 用原生 u128 乘積當參照，涵蓋多字與進位
        let vals: [u64; 6] = [1, 2, 0xFFFF_FFFF, 0x1_0000_0000, 0x1234_5678_9ABC, u64::MAX];
        for &a in &vals {
            for &b in &vals {
                let x = BigInteger::from_u64(a);
                let y = BigInteger::from_u64(b);
                let got = multiply_magnitudes(&x.magnitude, &y.magnitude);
                let want = Vec::from(BigInteger::from_u128(a as u128 * b as u128).magnitude);
                assert_eq!(got, want, "{a} * {b}");
            }
        }
    }

    #[test]
    fn multiply_magnitudes_is_commutative() {
        let a = [0x1234_5678, 0x9ABC_DEF0];
        let b = [0xFEDC_BA98, 0x7654_3210];
        assert_eq!(multiply_magnitudes(&a, &b), multiply_magnitudes(&b, &a));
    }

    #[test]
    fn is_power_of_two_predicate() {
        assert!(BigInteger::from_u32(1).is_power_of_two()); // 2^0
        assert!(BigInteger::from_u32(2).is_power_of_two());
        assert!(BigInteger::from_u32(8).is_power_of_two());
        assert!(BigInteger::from_u64(1 << 40).is_power_of_two());
        assert!(!BigInteger::from_u32(3).is_power_of_two()); // 0b11
        assert!(!BigInteger::from_u32(0).is_power_of_two()); // 零
        assert!(!BigInteger::from_i32(-8).is_power_of_two()); // 負數
    }

    #[test]
    fn divide_words_matches_shift() {
        // 非負數砍掉低 w 個字 == 右移 32·w 位（Shr 為 floor，正數下與截斷一致）
        let vals = [
            BigInteger::from_u128(0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00),
            BigInteger::from_u128(u128::MAX),
            BigInteger::from_u64(0xDEAD_BEEF_0000_0001),
            BigInteger::from_u32(0x8000_0001),
        ];
        for x in &vals {
            for w in 0usize..=5 {
                let got = x.divide_words(w);
                let expected = x >> (32 * w as u32);
                assert_eq!(got, expected, "x={x}, w={w}");
            }
        }
    }

    #[test]
    fn divide_words_edge_cases() {
        // w >= 字數 → 0
        let x = BigInteger::from_u64(0xDEAD_BEEF_0000_0001); // 2 個字
        assert_eq!(x.divide_words(2), BigInteger::from_u32(0));
        assert_eq!(x.divide_words(9), BigInteger::from_u32(0));
        // 零本身
        assert_eq!(BigInteger::from_u32(0).divide_words(0), BigInteger::from_u32(0));
        // 負數：截斷向零、符號保留（-(0x7EADBEEF_00000001) 砍低字 → -0x7EADBEEF）
        let neg = BigInteger::from_i64(-0x7EAD_BEEF_0000_0001);
        assert_eq!(neg.divide_words(1), BigInteger::from_i64(-0x7EAD_BEEF));
    }

    #[test]
    fn compare_to_skips_leading_zeros() {
        use core::cmp::Ordering;
        assert_eq!(compare_to(&[0, 0, 5], &[5]), Ordering::Equal); // 前導零不影響值
        assert_eq!(compare_to(&[0, 1, 0], &[1]), Ordering::Greater); // 2^32 > 1
        assert_eq!(compare_to(&[0, 0], &[0]), Ordering::Equal); // 皆為 0
        assert_eq!(compare_to(&[3], &[0, 0, 4]), Ordering::Less);
        assert_eq!(compare_to(&[0, 7], &[0, 0, 7]), Ordering::Equal);
    }

    #[test]
    fn inverse_u32_is_modular_inverse() {
        // d · inverse_u32(d) ≡ 1 (mod 2³²)，對各種奇數
        for d in [1u32, 3, 5, 7, 0x12345679, 0x8000_0001, 0xDEAD_BEEF, 0xFFFF_FFFF] {
            assert_eq!(d & 1, 1, "測資須為奇數 d={d:#x}");
            assert_eq!(d.wrapping_mul(inverse_u32(d)), 1, "d={d:#x}");
        }
    }

    #[test]
    fn multiply_monty_n_is_one_matches() {
        // r = x·y·R⁻¹ mod m  ⟺  r·2³² ≡ x·y (mod m)（R = 2³²）
        for &m in &[3u32, 5, 97, 0x8000_0001, 0xFFFF_FFFB] {
            let m_prime = inverse_u32(0u32.wrapping_sub(m)); // -m⁻¹ mod 2³²
            let samples = [0u32, 1, 2, m / 2, m - 1, 12345 % m, 0xFFFF % m];
            for &x in &samples {
                for &y in &samples {
                    let r = multiply_monty_n_is_one(x, y, m, m_prime);
                    assert!(r < m, "m={m} x={x} y={y} r={r}");
                    let lhs = ((r as u64) << 32) % m as u64;
                    let rhs = (x as u64 * y as u64) % m as u64;
                    assert_eq!(lhs, rhs, "m={m} x={x} y={y}");
                }
            }
        }
    }

    #[test]
    fn multiply_monty_matches() {
        // MonPro(a·R mod m, b) = a·b mod m（普通形式），R = 2^(32n)
        fn to_words(v: &BigInteger, n: usize) -> Vec<u32> {
            let mut w = vec![0u32; n];
            w[n - v.magnitude.len()..].copy_from_slice(&v.magnitude);
            w
        }
        let moduli = [
            BigInteger::from_u32(97),                    // n=1（走單字特例）
            BigInteger::from_u64(0x1_0000_0001),         // n=2
            BigInteger::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61", 16).unwrap(), // n=4
        ];
        let vals = [
            BigInteger::from_u32(0),
            BigInteger::from_u32(1),
            BigInteger::from_u64(0x1234_5678_9ABC),
            BigInteger::from_str_radix("A1B2C3D4E5F60718", 16).unwrap(),
        ];
        for m in &moduli {
            let n = m.magnitude.len();
            let m_prime = m.m_prime();
            for a in &vals {
                let a_mont = &(a << (32 * n as u32)) % m; // a·R mod m
                let x = to_words(&a_mont, n);
                for b in &vals {
                    let y = to_words(&(b % m), n); // b mod m
                    let mut acc = vec![0u32; n + 1];
                    let mut xx = x.clone();
                    multiply_monty(&mut acc, &mut xx, &y, &m.magnitude, m_prime, false);
                    let got = BigInteger::from_checked_magnitude(1, xx);
                    let expected = &(a * b) % m;
                    assert_eq!(got, expected, "m={m} a={a} b={b}");
                }
            }
        }
    }

    #[test]
    fn monty_domain_primitives() {
        // convert=false 與 mod_square_monty 都在 Montgomery 域運作：
        // 餵 Montgomery 形式的 a（= a·R mod m），域內運算後 montgomery_reduce 轉回，
        // 應等於普通形式的 a^e mod m / a² mod m。
        fn to_words(v: &BigInteger, n: usize) -> Vec<u32> {
            let mut w = vec![0u32; n];
            w[n - v.magnitude.len()..].copy_from_slice(&v.magnitude);
            w
        }
        fn from_monty(y_mont: &BigInteger, m: &BigInteger) -> BigInteger {
            let n = m.magnitude.len();
            let mut buf = to_words(y_mont, n);
            montgomery_reduce(&mut buf, &m.magnitude, m.m_prime());
            BigInteger::from_checked_magnitude(1, buf)
        }
        let moduli = [
            BigInteger::from_u32(97),                    // small_monty_modulus = true
            BigInteger::from_u64(0x1_0000_0001),
            BigInteger::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61", 16).unwrap(), // = false
        ];
        let raws = [
            BigInteger::from_u32(2),
            BigInteger::from_u64(0x1234_5678_9ABC),
            BigInteger::from_str_radix("A1B2C3D4E5F60718", 16).unwrap(),
        ];
        let exps = [1u32, 2, 3, 17, 100];
        for m in &moduli {
            let n = m.magnitude.len();
            for raw in &raws {
                let a = raw.rem_euclid(m); // 0 <= a < m
                let a_mont = &(&a << (32 * n as u32)) % m; // â = a·R mod m
                // 域內平方：â² → Montgomery a²；轉回 == a² mod m
                let sq = BigInteger::mod_square_monty(&a_mont, m);
                assert_eq!(from_monty(&sq, m), &(&a * &a) % m, "square m={m} a={a}");
                // 域內冪次(convert=false)：â^e → Montgomery a^e；轉回 == convert=true
                for &ev in &exps {
                    let e = BigInteger::from_u32(ev);
                    let y_false = BigInteger::mod_pow_monty(&a_mont, &e, m, false);
                    let expected = BigInteger::mod_pow_monty(&a, &e, m, true);
                    assert_eq!(from_monty(&y_false, m), expected, "pow m={m} a={a} e={ev}");
                }
            }
        }
    }

    #[test]
    fn mod_pow_monty_matches_barrett() {
        // 奇模數：Montgomery 路徑必與已驗證的 Barrett 路徑一致
        let odds = [
            BigInteger::from_u32(97),
            BigInteger::from_u64(0xFFFF_FFFF_FFFF_FFFB),
            BigInteger::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61", 16).unwrap(),
        ];
        let bases = [2i64, 3, 7, 1234567, -55];
        let exps = [1u32, 2, 3, 17, 65537, 123456];
        for m in &odds {
            for &bv in &bases {
                let base = BigInteger::from_i64(bv).rem_euclid(m); // 0 <= base < m
                for &ev in &exps {
                    let exp = BigInteger::from_u32(ev);
                    assert_eq!(
                        BigInteger::mod_pow_monty(&base, &exp, m, true),
                        BigInteger::mod_pow_barrett(&base, &exp, m),
                        "m={m} base={base} exp={exp}"
                    );
                }
            }
        }
    }

    #[test]
    fn montgomery_reduce_matches() {
        // reduce(a·R mod m) = a mod m（把 Montgomery 域轉回普通形式）
        fn to_words(v: &BigInteger, n: usize) -> Vec<u32> {
            let mut w = vec![0u32; n];
            w[n - v.magnitude.len()..].copy_from_slice(&v.magnitude);
            w
        }
        let moduli = [
            BigInteger::from_u32(97),
            BigInteger::from_u64(0x1_0000_0001),
            BigInteger::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61", 16).unwrap(),
        ];
        let vals = [
            BigInteger::from_u32(0),
            BigInteger::from_u32(1),
            BigInteger::from_u64(0x1234_5678_9ABC),
            BigInteger::from_str_radix("A1B2C3D4E5F60718", 16).unwrap(),
        ];
        for m in &moduli {
            let n = m.magnitude.len();
            let m_prime = m.m_prime();
            for a in &vals {
                let a_mont = &(a << (32 * n as u32)) % m; // a·R mod m（< m）
                let mut x = to_words(&a_mont, n);
                montgomery_reduce(&mut x, &m.magnitude, m_prime);
                let got = BigInteger::from_checked_magnitude(1, x);
                let expected = a % m;
                assert_eq!(got, expected, "m={m} a={a}");
            }
        }
    }

    #[test]
    fn square_monty_matches_multiply() {
        // square_monty(x) 必等於 multiply_monty(x, x)（後者已驗證，當 oracle）
        fn to_words(v: &BigInteger, n: usize) -> Vec<u32> {
            let mut w = vec![0u32; n];
            w[n - v.magnitude.len()..].copy_from_slice(&v.magnitude);
            w
        }
        let moduli = [
            BigInteger::from_u32(97),
            BigInteger::from_u64(0x1_0000_0001),
            BigInteger::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61", 16).unwrap(),
        ];
        let vals = [
            BigInteger::from_u32(0),
            BigInteger::from_u32(1),
            BigInteger::from_u64(0x1234_5678_9ABC),
            BigInteger::from_str_radix("A1B2C3D4E5F60718", 16).unwrap(),
        ];
        for m in &moduli {
            let n = m.magnitude.len();
            let m_prime = m.m_prime();
            for v in &vals {
                let x = to_words(&(v % m), n); // 任意 x < m 都成立
                let mut xs = x.clone();
                let mut acc1 = vec![0u32; n + 1];
                square_monty(&mut acc1, &mut xs, &m.magnitude, m_prime, false);

                let mut xm = x.clone();
                let y = x.clone();
                let mut acc2 = vec![0u32; n + 1];
                multiply_monty(&mut acc2, &mut xm, &y, &m.magnitude, m_prime, false);

                assert_eq!(
                    BigInteger::from_checked_magnitude(1, xs),
                    BigInteger::from_checked_magnitude(1, xm),
                    "m={m} v={v}"
                );
            }
        }
    }

    #[test]
    fn m_prime_property() {
        // m' 滿足 m_low · m' ≡ -1 (mod 2³²)，即 wrapping_mul == u32::MAX
        let odds = [
            BigInteger::from_u32(97),
            BigInteger::from_u64(0xFFFF_FFFF_FFFF_FFFB),
            BigInteger::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61", 16).unwrap(),
        ];
        for m in &odds {
            let m_low = *m.magnitude.last().unwrap();
            assert_eq!(m_low & 1, 1, "模數須為奇數 m={m}");
            let mp = m.m_prime();
            assert_eq!(m_low.wrapping_mul(mp), u32::MAX, "m={m}");
        }
    }

    #[test]
    fn get_window_list_reconstructs_exponent() {
        // 把視窗項串回整數：每項先接上 mul_t 的位元，再補 zeros 個 0 位元
        fn reconstruct(list: &[u32]) -> BigInteger {
            let mut e = BigInteger::from_u32(0);
            for &w in list {
                if w == u32::MAX {
                    break;
                }
                let mul_t = w & 0xFF;
                let zeros = w >> 8;
                e = &(&e << bit_len(mul_t)) + &BigInteger::from_u32(mul_t);
                e = &e << zeros;
            }
            e
        }

        let exps = [
            BigInteger::from_u32(1),
            BigInteger::from_u32(13),
            BigInteger::from_u32(0xFFFF_FFFF),
            BigInteger::from_u64(0x1234_5678_9ABC_DEF0), // 尾端有 0，測 zeros 收尾
            BigInteger::from_str_radix("FFEEDDCCBBAA99887766554433221100F0F0", 16).unwrap(),
        ];
        for e in &exps {
            for extra_bits in 0usize..=4 {
                let list = get_window_list(&e.magnitude, extra_bits);
                assert_eq!(reconstruct(&list), *e, "e={e}, extra_bits={extra_bits}");
            }
        }
    }

    #[test]
    fn reduce_barrett_matches_mod() {
        // 依 m 預算 Barrett 常數 mr / yu（正式版由 mod_pow_barrett 算一次）
        fn barrett_params(m: &BigInteger) -> (BigInteger, BigInteger) {
            let k = m.magnitude.len() as u32;
            let one = BigInteger::from_u32(1);
            let mr = &one << (32 * (k + 1)); // 2^(32(k+1))
            let hi = &one << (64 * k); // 2^(64k)
            let yu = &hi / m; // ⌊2^(64k) / m⌋
            (mr, yu)
        }

        let moduli = [
            BigInteger::from_u32(97),
            BigInteger::from_u64(0xFFFF_FFFB), // 接近 1 個字上限
            BigInteger::from_u64(0x1_0000_000F), // 2 個字
            BigInteger::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61", 16).unwrap(), // 多字大模數
        ];

        for m in &moduli {
            let (mr, yu) = barrett_params(m);
            let one = BigInteger::from_u32(1);
            let m_minus_1 = m - &one;
            // 涵蓋 x < m、= m、剛過 m、以及接近 m² 的大值（觸發估計路徑）
            let xs = [
                BigInteger::from_u32(0),
                one.clone(),
                m_minus_1.clone(),
                m.clone(),
                m + &one,
                &(m * &BigInteger::from_u32(2)) + &BigInteger::from_u32(3),
                &m_minus_1 * &m_minus_1, // (m-1)² ~ m²
                &(m * m) - &one,         // m² - 1
            ];
            for x in &xs {
                assert_eq!(
                    BigInteger::reduce_barrett(x, m, &mr, &yu),
                    x % m,
                    "m={m}, x={x}"
                );
            }
            // 乘積 sweep：x = a·b（a,b < m ⇒ x < m²），涵蓋 r1<r3 需要 mr 修正的情形
            for ai in 0u32..12 {
                let a = &(&m_minus_1 * &BigInteger::from_u32(0x2545_F491 ^ ai)) % m; // a ∈ [0, m)
                for bi in 0u32..12 {
                    let b = &(&m_minus_1 * &BigInteger::from_u32(0x9E37_79B9 ^ bi)) % m; // b ∈ [0, m)
                    let x = &a * &b; // x < m²
                    assert_eq!(BigInteger::reduce_barrett(&x, m, &mr, &yu), &x % m, "m={m}, x={x}");
                }
            }
        }
    }

    #[test]
    fn remainder_words_matches_mod() {
        // 留低 w 個字 == self mod 2^(32·w)；截斷向零，故對任意符號都與 `%` 一致
        let vals = [
            BigInteger::from_u128(0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00),
            BigInteger::from_i128(-0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00),
            BigInteger::from_u64(0xDEAD_BEEF_0000_0001),
        ];
        for x in &vals {
            for w in 0usize..=5 {
                let modulus = &BigInteger::from_u32(1) << (32 * w as u32); // 2^(32w)
                let got = x.remainder_words(w);
                let expected = x % &modulus;
                assert_eq!(got, expected, "x={x}, w={w}");
            }
        }
    }

    #[test]
    fn remainder_words_trims_leading_zero_words() {
        // 留下的高位字為零 → 必須修剪：0x1_00000000_00000005 留低 2 字 [0,5] → 5
        let x = BigInteger::from_u128(0x1_0000_0000_0000_0005);
        assert_eq!(x.remainder_words(2), BigInteger::from_u32(5));

        // 留下的字全為零 → 必須歸零（且 sign 正規化成 0）：2·2^64 留低 2 字 [0,0] → 0
        let y = BigInteger::from_u128(0x2_0000_0000_0000_0000);
        assert_eq!(y.remainder_words(2), BigInteger::from_u32(0));

        // w == 0 → self mod 1 == 0
        assert_eq!(x.remainder_words(0), BigInteger::from_u32(0));
        // w >= 字數 → 整個 self
        assert_eq!(x.remainder_words(9), x);
    }

    #[test]
    fn and_not_basic() {
        // 基本遮罩：清掉 other 中為 1 的位元
        assert_eq!(
            BigInteger::from_u32(0b1110).and_not(&BigInteger::from_u32(0b0110)),
            BigInteger::from_u32(0b1000)
        );
        // a & !a = 0
        let a = BigInteger::from_u32(0xDEAD_BEEF);
        assert_eq!(a.and_not(&a), BigInteger::from_u32(0));
        // a & !0 = a
        assert_eq!(a.and_not(&BigInteger::from_u32(0)), a);

        // 對拍 native i64（含負數的二補數語義）：a & !b
        for a in [-13i64, -1, 0, 5, 42, 255] {
            for b in [-8i64, -1, 0, 3, 42, 128] {
                let expected = a & !b;
                let got = BigInteger::from_i64(a).and_not(&BigInteger::from_i64(b));
                assert_eq!(got, BigInteger::from_i64(expected), "a={a}, b={b}");
            }
        }
    }

    #[test]
    fn hash_matches_eq() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn hash_of(x: &BigInteger) -> u64 {
            let mut h = DefaultHasher::new();
            x.hash(&mut h);
            h.finish()
        }

        // 相等的值（不同建構路徑）必須雜湊相同
        let a = BigInteger::from_i64(1_000_000_007);
        let prod = &BigInteger::from_i32(1_000_000) * &BigInteger::from_i32(1000);
        let b = &prod + &BigInteger::from_i32(7);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));

        // 正負同絕對值不得相等，雜湊也應不同（極大機率）
        assert_ne!(hash_of(&BigInteger::from_i32(42)), hash_of(&BigInteger::from_i32(-42)));

        // 能當 HashSet 的 key
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(BigInteger::from_i32(-42));
        set.insert(BigInteger::from_i32(42));
        set.insert(BigInteger::from_i64(1_000_000_007));
        assert!(set.contains(&b)); // 用等值的不同實例查得到
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn pow_basic() {
        assert_eq!(BigInteger::from_i32(2).pow(10), BigInteger::from_i32(1024));
        assert_eq!(BigInteger::from_i32(3).pow(4), BigInteger::from_i32(81));
        assert_eq!(BigInteger::from_i32(-2).pow(3), BigInteger::from_i32(-8)); // 奇次負底 → 負
        assert_eq!(BigInteger::from_i32(-2).pow(4), BigInteger::from_i32(16)); // 偶次負底 → 正
        assert_eq!(BigInteger::from_i32(5).pow(0), BigInteger::from_i32(1)); // x^0 = 1
        assert_eq!(BigInteger::from_i32(0).pow(0), BigInteger::from_i32(1)); // 0^0 = 1（慣例）
        assert_eq!(BigInteger::from_i32(0).pow(5), BigInteger::from_i32(0)); // 0^n = 0
        assert_eq!(BigInteger::from_i32(7).pow(1), BigInteger::from_i32(7)); // x^1 = x
    }

    #[test]
    fn pow_matches_native() {
        // 對拍 native i128：底 −6..=6、指數 0..=12，避開 i128 溢位
        for base in -6i128..=6 {
            for e in 0u32..=12 {
                let expected = base.pow(e);
                let got = BigInteger::from_i128(base).pow(e);
                assert_eq!(got, BigInteger::from_i128(expected), "base={base}, e={e}");
            }
        }
    }

    #[test]
    fn pow_power_of_two_shortcut() {
        // 2 的冪底走位移捷徑，須與逐位乘法版一致
        assert_eq!(BigInteger::from_i32(2).pow(64), BigInteger::from_u128(1u128 << 64));
        assert_eq!(BigInteger::from_i32(8).pow(20), BigInteger::from_i32(2).pow(60)); // 8^20 = 2^60
    }

    #[test]
    fn square_magnitude_matches_multiply() {
        // 平方須與通用乘法 x·x 完全一致（含滿進位、跨字、含零字）
        let cases: [&[u32]; 10] = [
            &[1],
            &[u32::MAX],
            &[0x1_0000],
            &[1, 0],
            &[u32::MAX, u32::MAX],
            &[0x1234_5678, 0x9ABC_DEF0],
            &[1, 2, 3],
            &[u32::MAX, 0, u32::MAX],
            &[0xDEAD_BEEF, 0x0000_0001, 0xFFFF_FFFF, 0x8000_0000],
            &[u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX],
        ];
        for x in cases {
            assert_eq!(square_magnitude(x), multiply_magnitudes(x, x), "x = {x:?}");
        }
    }

    #[test]
    fn square_magnitude_matches_u128_reference() {
        // 小值：拿原生 u128 平方當獨立參照
        let vals: [u64; 6] = [1, 2, 0xFFFF_FFFF, 0x1_0000_0000, 0x1234_5678_9ABC, u64::MAX];
        for &a in &vals {
            let x = BigInteger::from_u64(a);
            let got = square_magnitude(&x.magnitude);
            let want = Vec::from(BigInteger::from_u128(a as u128 * a as u128).magnitude);
            assert_eq!(got, want, "{a}²");
        }
    }

    #[test]
    fn square_method_matches_reference() {
        let vals = [0i64, 1, -1, 2, -2, 8, -8, 7, -7, 1024, 0xFFFF_FFFF, -(0xFFFF_FFFFi64), 1 << 40];
        for &a in &vals {
            let x = BigInteger::from_i64(a);
            // 對照原生 i128 平方（負數平方為正）
            assert_eq!(x.square(), BigInteger::from_i128(a as i128 * a as i128), "{a}²");
            // 與 &x * &x 一致
            assert_eq!(x.square(), &x * &x, "{a}² method vs *");
        }
    }

    #[test]
    fn square_magnitude_fuzz_vs_multiply() {
        // 用簡單 LCG 產生各種長度的 magnitude，對照通用乘法
        let mut state = 0x1234_5678u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 32) as u32
        };
        for len in 1..=8usize {
            for _ in 0..20 {
                let mut x: Vec<u32> = (0..len).map(|_| next()).collect();
                if x[0] == 0 {
                    x[0] = 1; // 確保無前導零
                }
                assert_eq!(square_magnitude(&x), multiply_magnitudes(&x, &x), "x = {x:?}");
            }
        }
    }

    #[test]
    fn mul_operator_signs() {
        assert_eq!(&BigInteger::from_i32(5) * &BigInteger::from_i32(3), BigInteger::from_i32(15));
        assert_eq!(&BigInteger::from_i32(-5) * &BigInteger::from_i32(3), BigInteger::from_i32(-15));
        assert_eq!(&BigInteger::from_i32(5) * &BigInteger::from_i32(-3), BigInteger::from_i32(-15));
        assert_eq!(&BigInteger::from_i32(-5) * &BigInteger::from_i32(-3), BigInteger::from_i32(15));
    }

    #[test]
    fn mul_with_zero() {
        assert_eq!(&BigInteger::from_i32(0) * &BigInteger::from_i32(7), BigInteger::from_i32(0));
        assert_eq!(&BigInteger::from_i32(7) * &BigInteger::from_i32(0), BigInteger::from_i32(0));
    }

    #[test]
    fn mul_matches_i128_reference() {
        // 用原生 i128 乘積當參照，涵蓋各種符號與大小組合（值控制在乘積不溢位 i128）
        let vals = [0i64, 1, -1, 7, -7, 0xFFFF_FFFF, -(0xFFFF_FFFFi64), 1 << 40, -(1 << 40)];
        for &a in &vals {
            for &b in &vals {
                let got = &BigInteger::from_i64(a) * &BigInteger::from_i64(b);
                let want = BigInteger::from_i128(a as i128 * b as i128);
                assert_eq!(got, want, "{a} * {b}");
            }
        }
    }

    #[test]
    fn mul_is_commutative() {
        let a = BigInteger::from_i64(-123456789012);
        let b = BigInteger::from_i64(987654321);
        assert_eq!(&a * &b, &b * &a);
    }

    #[test]
    fn mul_shortcuts_match_reference() {
        // 冪次捷徑（含 2^k 運算元）與平方捷徑須與原生 i128 一致
        let vals = [
            1i64, -1, 2, -2, 8, -8, 7, -7, 1024, -1024,
            0xFFFF_FFFF, -(0xFFFF_FFFFi64), 1 << 40, -(1 << 40),
        ];
        for &a in &vals {
            for &b in &vals {
                let got = &BigInteger::from_i64(a) * &BigInteger::from_i64(b);
                let want = BigInteger::from_i128(a as i128 * b as i128);
                assert_eq!(got, want, "{a} * {b}");
            }
        }
        // 平方捷徑：&x * &x 同址 → 走 square_magnitude（非 2^k 者）
        for &a in &vals {
            let x = BigInteger::from_i64(a);
            assert_eq!(&x * &x, BigInteger::from_i128(a as i128 * a as i128), "{a}²");
        }
    }

    #[test]
    fn shl_within_word() {
        assert_eq!(&BigInteger::from_u32(1) << 1, BigInteger::from_u32(2));
        assert_eq!(&BigInteger::from_u32(5) << 3, BigInteger::from_u32(40));
    }

    #[test]
    fn shl_whole_words() {
        // 剛好整字倍數（n_bits == 0）
        assert_eq!(&BigInteger::from_u32(1) << 32, BigInteger::from_u64(1 << 32));
        assert_eq!(&BigInteger::from_u32(1) << 64, BigInteger::from_u128(1 << 64));
    }

    #[test]
    fn shl_cross_word_carry() {
        // 移出頂端需要新前導字：0x8000_0000 << 1 = 0x1_0000_0000
        assert_eq!(&BigInteger::from_u32(0x8000_0000) << 1, BigInteger::from_u64(1 << 32));
    }

    #[test]
    fn shl_preserves_sign() {
        assert_eq!(&BigInteger::from_i32(-1) << 4, BigInteger::from_i32(-16));
    }

    #[test]
    fn shl_zero_and_by_zero() {
        assert_eq!(&BigInteger::from_i32(0) << 10, BigInteger::from_i32(0));
        assert_eq!(&BigInteger::from_i32(7) << 0, BigInteger::from_i32(7));
    }

    #[test]
    fn shl_matches_i128_reference() {
        // a << n == a * 2^n；值與位移量控制在不溢位 i128
        let vals = [0i64, 1, -1, 7, -7, 0xFFFF_FFFF, -(0xFFFF_FFFFi64)];
        for &a in &vals {
            for n in [0u32, 1, 5, 31, 32, 33, 64] {
                let got = &BigInteger::from_i64(a) << n;
                let want = BigInteger::from_i128((a as i128) << n);
                assert_eq!(got, want, "{a} << {n}");
            }
        }
    }

    #[test]
    fn shr_within_word() {
        assert_eq!(&BigInteger::from_u32(40) >> 3, BigInteger::from_u32(5));
        assert_eq!(&BigInteger::from_u32(2) >> 1, BigInteger::from_u32(1));
    }

    #[test]
    fn shr_whole_words() {
        // 剛好整字倍數（bit_shift == 0）
        assert_eq!(&BigInteger::from_u64(1 << 32) >> 32, BigInteger::from_u32(1));
        assert_eq!(&BigInteger::from_u128(1 << 64) >> 64, BigInteger::from_u32(1));
    }

    #[test]
    fn shr_positive_truncates_toward_zero() {
        // 正數：等同截斷，低位直接丟棄
        assert_eq!(&BigInteger::from_u32(9) >> 3, BigInteger::from_u32(1)); // 9/8 = 1
        assert_eq!(&BigInteger::from_u32(7) >> 3, BigInteger::from_u32(0)); // 7/8 = 0
    }

    #[test]
    fn shr_negative_floors_toward_neg_inf() {
        // 負數：向負無窮取整（非整除時比截斷多退一）
        assert_eq!(&BigInteger::from_i32(-8) >> 3, BigInteger::from_i32(-1)); // 整除，-1
        assert_eq!(&BigInteger::from_i32(-9) >> 3, BigInteger::from_i32(-2)); // floor(-1.125) = -2
        assert_eq!(&BigInteger::from_i32(-1) >> 1, BigInteger::from_i32(-1)); // floor(-0.5) = -1
    }

    #[test]
    fn shr_shifts_everything_out() {
        // 移出位元超過整個 magnitude：非負 → 0；負 → -1
        assert_eq!(&BigInteger::from_u32(5) >> 100, BigInteger::from_u32(0));
        assert_eq!(&BigInteger::from_i32(-5) >> 100, BigInteger::from_i32(-1));
        // 邊界：剛好等於容量（單字 → 32 位）
        assert_eq!(&BigInteger::from_u32(0xFFFF_FFFF) >> 32, BigInteger::from_u32(0));
        assert_eq!(&BigInteger::from_i32(-1) >> 32, BigInteger::from_i32(-1));
    }

    #[test]
    fn shr_zero_and_by_zero() {
        assert_eq!(&BigInteger::from_i32(0) >> 10, BigInteger::from_i32(0));
        assert_eq!(&BigInteger::from_i32(7) >> 0, BigInteger::from_i32(7));
        assert_eq!(&BigInteger::from_i32(-7) >> 0, BigInteger::from_i32(-7));
    }

    #[test]
    fn shr_cross_word() {
        // 跨字補位：2^32 >> 1 = 2^31
        assert_eq!(&BigInteger::from_u64(1 << 32) >> 1, BigInteger::from_u64(1 << 31));
        // 高位相消縮短：(2^32 + 1) >> 1 = 2^31
        assert_eq!(&BigInteger::from_u64((1 << 32) + 1) >> 1, BigInteger::from_u64(1 << 31));
    }

    #[test]
    fn shr_matches_i128_reference() {
        // a >> n == floor(a / 2^n)；原生 i128 的算術右移即 floor
        let vals = [0i64, 1, -1, 7, -7, 255, -256, 0xFFFF_FFFF, -(0xFFFF_FFFFi64), 1 << 40, -(1 << 40)];
        for &a in &vals {
            for n in [0u32, 1, 5, 31, 32, 33, 40, 41, 64] {
                let got = &BigInteger::from_i64(a) >> n;
                let want = BigInteger::from_i128((a as i128) >> n);
                assert_eq!(got, want, "{a} >> {n}");
            }
        }
    }

    #[test]
    fn shl_shr_round_trip() {
        // (a << n) >> n == a（左移不丟位，右移可完整還原）
        let vals = [0i64, 1, -1, 12345, -12345, 0xFFFF_FFFF, -(0xFFFF_FFFFi64)];
        for &a in &vals {
            for n in [0u32, 1, 7, 31, 32, 40] {
                let a = BigInteger::from_i64(a);
                assert_eq!(&(&a << n) >> n, a);
            }
        }
    }

    #[test]
    fn shift_right_in_place_basic() {
        // 純字內位移（n < 32）
        let mut m = vec![0x0000_0001u32, 0x0000_0000]; // 2^32
        shift_right_in_place(&mut m, 1);
        assert_eq!(m, vec![0, 0x8000_0000]); // 2^31

        // 整字位移（n 為 32 倍數）
        let mut m = vec![3u32, 0]; // 3 * 2^32
        shift_right_in_place(&mut m, 32);
        assert_eq!(m, vec![0, 3]);

        // 混合（word + bit）：floor((2^32 + 2^31) / 2^33) = 0
        let mut m = vec![1u32, 0x8000_0000];
        shift_right_in_place(&mut m, 33);
        assert_eq!(m, vec![0, 0]);
    }

    #[test]
    fn shift_right_in_place_matches_allocating() {
        // 原地版右移後去前導零，應與配置版 shift_right_magnitude 一致
        let cases: [&[u32]; 4] = [
            &[0x1234_5678, 0x9ABC_DEF0],
            &[u32::MAX, u32::MAX, u32::MAX],
            &[1, 0, 0],
            &[0xFFFF_FFFF, 0x0000_0001],
        ];
        for x in cases {
            for n in [1usize, 5, 31, 32, 33, 63, 64] {
                if n >= x.len() * 32 {
                    continue;
                }
                let mut m = x.to_vec();
                shift_right_in_place(&mut m, n);
                assert_eq!(trim_leading_zeros(m), shift_right_magnitude(x, n), "x={x:?} n={n}");
            }
        }
    }

    #[test]
    fn shift_right_one_in_place_basic() {
        let mut m = vec![0x0000_0002u32];
        shift_right_one_in_place(&mut m);
        assert_eq!(m, vec![1]);

        // 跨字：2^32 >> 1 = 2^31，低位鄰字的最低位補到高位鄰字頂端
        let mut m = vec![1u32, 0x0000_0000];
        shift_right_one_in_place(&mut m);
        assert_eq!(m, vec![0, 0x8000_0000]);

        // 奇數最高字：最低位落到下一字頂端
        let mut m = vec![0x0000_0003u32, 0x0000_0000];
        shift_right_one_in_place(&mut m);
        assert_eq!(m, vec![1, 0x8000_0000]);
    }

    #[test]
    fn shift_right_one_matches_shift_right_in_place() {
        // 1 位特化版須與通用版 shift_right_in_place(_, 1) 結果相同
        let cases: [&[u32]; 4] = [
            &[0x1234_5678, 0x9ABC_DEF0],
            &[u32::MAX, u32::MAX, u32::MAX],
            &[1, 0, 0],
            &[0xFFFF_FFFF, 0x0000_0001],
        ];
        for x in cases {
            let mut a = x.to_vec();
            let mut b = x.to_vec();
            shift_right_one_in_place(&mut a);
            shift_right_in_place(&mut b, 1);
            assert_eq!(a, b, "x={x:?}");
        }
    }

    // 拿原生 u128 的 / 與 % 對照：div_magnitudes 回傳 (商, 餘)，皆已 trim
    fn check_divide(dividend: u128, divisor: u128) {
        let x = Vec::from(BigInteger::from_u128(dividend).magnitude);
        let y = Vec::from(BigInteger::from_u128(divisor).magnitude);
        let (q, r) = div_magnitudes(&x, &y);
        assert_eq!(
            q,
            Vec::from(BigInteger::from_u128(dividend / divisor).magnitude),
            "{dividend} / {divisor}"
        );
        assert_eq!(
            r,
            Vec::from(BigInteger::from_u128(dividend % divisor).magnitude),
            "{dividend} % {divisor}"
        );
    }

    #[test]
    fn divide_magnitude_matches_u128() {
        let cases: [(u128, u128); 14] = [
            (10, 3),
            (3, 10), // 被除數 < 除數：商 0、餘數 = 被除數
            (100, 10), // 整除
            (7, 7), // 相等：商 1、餘數 0
            (2, 1),
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF),
            (1 << 64, 1 << 32),
            (12_345_678_901_234_567_890, 987_654_321),
            ((1u128 << 100) + 12345, (1u128 << 50) + 7),
            (u128::MAX, 3),
            (u128::MAX, u128::MAX),
            (u128::MAX, 0xFFFF_FFFF_FFFF_FFFF),
            (0x1_0000_0000_0000_0000, 2),
            (999_999_999_999, 1),
        ];
        for (a, b) in cases {
            check_divide(a, b);
        }
    }

    #[test]
    fn divide_magnitude_fuzz() {
        // LCG 產生 128-bit 被除數與 64-bit 除數，跟原生 u128 對照
        let mut state = 0x9E37_79B9u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            state
        };
        for _ in 0..500 {
            let a = ((next() as u128) << 64) | (next() as u128);
            let b = (next() as u128).max(1); // 除數非零
            if a == 0 {
                continue;
            }
            check_divide(a, b);
        }
    }

    #[test]
    fn div_rem_matches_i128_reference() {
        // 截斷除法：對照原生 i128 的 / 與 %，涵蓋各種符號與大小
        let vals = [
            0i64, 1, -1, 7, -7, 8, -8, 100, -100,
            0xFFFF_FFFF, -(0xFFFF_FFFFi64), 1 << 40, -(1 << 40), i64::MAX, i64::MIN,
        ];
        for &a in &vals {
            for &b in &vals {
                if b == 0 {
                    continue; // 零除另外測
                }
                let (x, y) = (BigInteger::from_i64(a), BigInteger::from_i64(b));
                let (q, r) = x.div_rem(&y);
                assert_eq!(q, BigInteger::from_i128(a as i128 / b as i128), "{a} / {b}");
                assert_eq!(r, BigInteger::from_i128(a as i128 % b as i128), "{a} % {b}");
                // 運算子須與 div_rem 一致
                assert_eq!(&x / &y, q, "{a} / {b} 運算子");
                assert_eq!(&x % &y, r, "{a} % {b} 運算子");
                // 商 × 除數 + 餘 == 被除數
                assert_eq!(&(&q * &y) + &r, x, "{a} = q*b + r");
            }
        }
    }

    #[test]
    fn buffer_too_small_display() {
        assert_eq!(
            BufferTooSmall { needed: 2, available: 1 }.to_string(),
            "buffer too small: need 2 bytes, got 1"
        );
    }

    #[test]
    fn parse_error_display() {
        assert_eq!(
            ParseBigIntegerError::Empty.to_string(),
            "cannot parse integer from empty string"
        );
        assert_eq!(
            ParseBigIntegerError::InvalidDigit { index: 3, ch: 'x' }.to_string(),
            "invalid digit 'x' at position 3"
        );
    }

    #[test]
    fn from_str_radix_basic() {
        assert_eq!(BigInteger::from_str_radix("0", 10).unwrap(), BigInteger::from_i32(0));
        assert_eq!(BigInteger::from_str_radix("255", 10).unwrap(), BigInteger::from_u32(255));
        assert_eq!(BigInteger::from_str_radix("ff", 16).unwrap(), BigInteger::from_u32(255));
        assert_eq!(BigInteger::from_str_radix("FF", 16).unwrap(), BigInteger::from_u32(255)); // 大寫
        assert_eq!(BigInteger::from_str_radix("1010", 2).unwrap(), BigInteger::from_u32(10));
        assert_eq!(BigInteger::from_str_radix("z", 36).unwrap(), BigInteger::from_u32(35));
        assert_eq!(BigInteger::from_str_radix("-100", 10).unwrap(), BigInteger::from_i32(-100));
        assert_eq!(BigInteger::from_str_radix("+42", 10).unwrap(), BigInteger::from_i32(42));
        assert_eq!(BigInteger::from_str_radix("-0", 10).unwrap(), BigInteger::from_i32(0)); // 無負零
        assert_eq!(BigInteger::from_str_radix("007", 10).unwrap(), BigInteger::from_u32(7)); // 前導零
    }

    #[test]
    fn from_str_radix_errors() {
        assert_eq!(BigInteger::from_str_radix("", 10), Err(ParseBigIntegerError::Empty));
        assert_eq!(BigInteger::from_str_radix("-", 10), Err(ParseBigIntegerError::Empty));
        assert_eq!(BigInteger::from_str_radix("+", 10), Err(ParseBigIntegerError::Empty));
        // 非法字元
        assert_eq!(
            BigInteger::from_str_radix("12x", 10),
            Err(ParseBigIntegerError::InvalidDigit { index: 2, ch: 'x' })
        );
        // 位數超出 radix：'8' 在八進制
        assert_eq!(
            BigInteger::from_str_radix("18", 8),
            Err(ParseBigIntegerError::InvalidDigit { index: 1, ch: '8' })
        );
        // 錯誤位置換算回原始 s（符號 offset）
        assert_eq!(
            BigInteger::from_str_radix("-12x", 10),
            Err(ParseBigIntegerError::InvalidDigit { index: 3, ch: 'x' })
        );
    }

    #[test]
    fn from_str_trait_and_parse() {
        // .parse() 走 radix 10
        let a: BigInteger = "123456789012345678901234567890".parse().unwrap();
        let b = BigInteger::from_str_radix("123456789012345678901234567890", 10).unwrap();
        assert_eq!(a, b);
        // 超出原生 u128 也能解析：2^128
        let big: BigInteger = "340282366920938463463374607431768211456".parse().unwrap();
        assert_eq!(big, &BigInteger::from_u128(u128::MAX) + &BigInteger::from_u32(1));
    }

    #[test]
    fn from_str_radix_roundtrip_decimal() {
        // 十進制：i128 → Display 字串 → 解析回來（涵蓋各符號與 i128::MIN）
        let vals = [0i128, 1, -1, 255, -256, 123456789, -987654321, i128::MAX, i128::MIN];
        for &v in &vals {
            let parsed = BigInteger::from_str_radix(&v.to_string(), 10).unwrap();
            assert_eq!(parsed, BigInteger::from_i128(v), "{v}");
        }
    }

    #[test]
    fn from_str_radix_roundtrip_hex() {
        // 十六進制（正數，用原生 {:x} 產生字串）
        let vals = [0u128, 1, 255, 0xDEAD_BEEF, u128::MAX];
        for &v in &vals {
            let parsed = BigInteger::from_str_radix(&format!("{v:x}"), 16).unwrap();
            assert_eq!(parsed, BigInteger::from_u128(v), "{v:x}");
        }
    }

    #[test]
    fn from_bytes_unsigned_top_bit_is_data() {
        // 關鍵差異：unsigned 版不把最高位當符號
        assert_eq!(BigInteger::from_bytes_be_unsigned(&[0x80]), BigInteger::from_u32(128));
        assert_eq!(BigInteger::from_bytes_be(&[0x80]), BigInteger::from_i32(-128)); // 對照 signed
        assert_eq!(BigInteger::from_bytes_be_unsigned(&[0xFF]), BigInteger::from_u32(255));
        // 多位元組
        assert_eq!(BigInteger::from_bytes_be_unsigned(&[0xFF, 0xFF]), BigInteger::from_u32(0xFFFF));
        // LE：最高位元組在尾端
        assert_eq!(BigInteger::from_bytes_le_unsigned(&[0x00, 0x80]), BigInteger::from_u32(0x8000));
        assert_eq!(BigInteger::from_bytes_le_unsigned(&[0x34, 0x12]), BigInteger::from_u32(0x1234));
        // 空 / 全零 → 0
        assert_eq!(BigInteger::from_bytes_be_unsigned(&[]), BigInteger::from_u32(0));
        assert_eq!(BigInteger::from_bytes_le_unsigned(&[0, 0, 0]), BigInteger::from_u32(0));
    }

    #[test]
    fn byte_length_matches_output() {
        // signed：byte_length() 須等於 to_bytes_be() 實際長度
        let vals = [
            0i128, 1, -1, 127, 128, -128, -129, 255, -256, 256,
            0xDEAD_BEEF, -(0xDEAD_BEEFi128), 1 << 64, -(1i128 << 64), i128::MAX, i128::MIN,
        ];
        for &v in &vals {
            let n = BigInteger::from_i128(v);
            assert_eq!(n.byte_length(), n.to_bytes_be().len(), "signed {v}");
        }
        // unsigned：byte_length_unsigned() 須等於 to_bytes_be_unsigned() 實際長度
        let uvals = [0u128, 1, 128, 255, 256, 0x8000, 0xDEAD_BEEF, u128::MAX];
        for &v in &uvals {
            let n = BigInteger::from_u128(v);
            assert_eq!(n.byte_length_unsigned(), n.to_bytes_be_unsigned().len(), "unsigned {v}");
        }
        // 負數 unsigned 長度只看絕對值
        assert_eq!(BigInteger::from_i32(-128).byte_length_unsigned(), 1);
        assert_eq!(BigInteger::from_i32(-256).byte_length_unsigned(), 2);
    }

    #[test]
    fn to_bytes_be_specific() {
        // 非負：最高位為 1 → 前補 0x00
        assert_eq!(BigInteger::from_i32(0).to_bytes_be(), vec![0]);
        assert_eq!(BigInteger::from_i32(127).to_bytes_be(), vec![0x7F]);
        assert_eq!(BigInteger::from_i32(128).to_bytes_be(), vec![0x00, 0x80]);
        assert_eq!(BigInteger::from_i32(255).to_bytes_be(), vec![0x00, 0xFF]);
        assert_eq!(BigInteger::from_i32(256).to_bytes_be(), vec![0x01, 0x00]);
        // 負：兩補數，必要時前補 0xFF
        assert_eq!(BigInteger::from_i32(-1).to_bytes_be(), vec![0xFF]);
        assert_eq!(BigInteger::from_i32(-128).to_bytes_be(), vec![0x80]);
        assert_eq!(BigInteger::from_i32(-129).to_bytes_be(), vec![0xFF, 0x7F]);
        assert_eq!(BigInteger::from_i32(-256).to_bytes_be(), vec![0xFF, 0x00]);
        // unsigned：128 不補 0（最高位是資料）
        assert_eq!(BigInteger::from_u32(128).to_bytes_be_unsigned(), vec![0x80]);
        assert_eq!(BigInteger::from_u32(0).to_bytes_be_unsigned(), vec![0]);
        // LE 是 BE 反轉
        assert_eq!(BigInteger::from_i32(-129).to_bytes_le(), vec![0x7F, 0xFF]);
    }

    #[test]
    fn to_bytes_into_matches_allocating() {
        // _into 版寫進 buffer 前端，回傳長度，內容須與配置版一致
        let vals = [
            0i128, 1, -1, 127, 128, -128, -129, 255, -256, 256,
            0xDEAD_BEEF, -(0xDEAD_BEEFi128), 1 << 64, -(1i128 << 64), i128::MAX, i128::MIN,
        ];
        for &v in &vals {
            let n = BigInteger::from_i128(v);
            let mut buf = [0u8; 32]; // 刻意比需要大
            // signed BE / LE
            let len = n.to_bytes_be_into(&mut buf);
            assert_eq!(&buf[..len], n.to_bytes_be().as_slice(), "be {v}");
            assert_eq!(len, n.byte_length(), "be len {v}");
            let len = n.to_bytes_le_into(&mut buf);
            assert_eq!(&buf[..len], n.to_bytes_le().as_slice(), "le {v}");
            // unsigned BE / LE
            let len = n.to_bytes_be_unsigned_into(&mut buf);
            assert_eq!(&buf[..len], n.to_bytes_be_unsigned().as_slice(), "be_u {v}");
            assert_eq!(len, n.byte_length_unsigned(), "be_u len {v}");
            let len = n.to_bytes_le_unsigned_into(&mut buf);
            assert_eq!(&buf[..len], n.to_bytes_le_unsigned().as_slice(), "le_u {v}");
        }
    }

    #[test]
    fn to_bytes_into_exact_buffer() {
        // 剛好 byte_length() 大小的 buffer 也能用
        let n = BigInteger::from_i32(128);
        let mut buf = vec![0u8; n.byte_length()];
        let len = n.to_bytes_be_into(&mut buf);
        assert_eq!(len, 2);
        assert_eq!(buf, vec![0x00, 0x80]);
    }

    #[test]
    #[should_panic(expected = "buffer too small")]
    fn to_bytes_be_into_panics_when_too_small() {
        let n = BigInteger::from_i32(128); // 需要 2 bytes
        let mut buf = [0u8; 1];
        n.to_bytes_be_into(&mut buf);
    }

    #[test]
    fn try_to_bytes_into_ok_and_err() {
        let n = BigInteger::from_i32(128); // 需要 2 bytes

        // 夠大 → Ok(寫入長度)，內容正確
        let mut buf = [0u8; 4];
        assert_eq!(n.try_to_bytes_be_into(&mut buf), Ok(2));
        assert_eq!(&buf[..2], &[0x00, 0x80]);

        // 太小 → Err(帶需要 vs 提供的長度)，不 panic
        let mut small = [0u8; 1];
        assert_eq!(
            n.try_to_bytes_be_into(&mut small),
            Err(BufferTooSmall { needed: 2, available: 1 })
        );

        // 其餘三個變體的 Err 也帶正確長度
        assert_eq!(n.try_to_bytes_le_into(&mut small).unwrap_err().needed, 2);
        assert_eq!(n.try_to_bytes_be_unsigned_into(&mut small), Ok(1)); // 128 unsigned 只要 1 byte
    }

    #[test]
    fn to_from_bytes_roundtrip_signed() {
        let vals = [
            0i128, 1, -1, 127, 128, -128, -129, 255, -256, 256, 0xDEAD, -0xDEAD,
            1 << 64, -(1i128 << 64), i128::MAX, i128::MIN,
        ];
        for &v in &vals {
            let n = BigInteger::from_i128(v);
            assert_eq!(BigInteger::from_bytes_be(&n.to_bytes_be()), n, "{v} be");
            assert_eq!(BigInteger::from_bytes_le(&n.to_bytes_le()), n, "{v} le");
        }
    }

    #[test]
    fn to_from_bytes_roundtrip_unsigned() {
        let vals = [0u128, 1, 128, 255, 256, 0x8000, 0xDEAD_BEEF, u128::MAX];
        for &v in &vals {
            let n = BigInteger::from_u128(v);
            assert_eq!(BigInteger::from_bytes_be_unsigned(&n.to_bytes_be_unsigned()), n, "{v} be");
            assert_eq!(BigInteger::from_bytes_le_unsigned(&n.to_bytes_le_unsigned()), n, "{v} le");
        }
    }

    #[test]
    fn to_bytes_unsigned_matches_native() {
        // 正數對照原生 to_be_bytes（去前導零）
        let vals = [1u128, 255, 256, 0xDEAD_BEEF, u128::MAX];
        for &v in &vals {
            let native = v.to_be_bytes();
            let start = native.iter().position(|&b| b != 0).unwrap();
            assert_eq!(BigInteger::from_u128(v).to_bytes_be_unsigned(), native[start..].to_vec(), "{v}");
        }
    }

    #[test]
    fn from_bytes_unsigned_matches_u128() {
        // 拿原生 u128 的 big-endian / little-endian 位元組當對照
        let vals = [0u128, 1, 255, 0x8000, 0xDEAD_BEEF, u128::MAX];
        for &v in &vals {
            let be = v.to_be_bytes();
            let le = v.to_le_bytes();
            assert_eq!(BigInteger::from_bytes_be_unsigned(&be), BigInteger::from_u128(v), "{v} be");
            assert_eq!(BigInteger::from_bytes_le_unsigned(&le), BigInteger::from_u128(v), "{v} le");
        }
    }

    #[test]
    fn to_str_radix_basic() {
        assert_eq!(BigInteger::from_i32(0).to_str_radix(10), "0");
        assert_eq!(BigInteger::from_u32(255).to_str_radix(10), "255");
        assert_eq!(BigInteger::from_u32(255).to_str_radix(16), "ff");
        assert_eq!(BigInteger::from_u32(10).to_str_radix(2), "1010");
        assert_eq!(BigInteger::from_u32(35).to_str_radix(36), "z");
        assert_eq!(BigInteger::from_i32(-100).to_str_radix(10), "-100");
        assert_eq!(BigInteger::from_i32(-5).to_str_radix(2), "-101");
    }

    #[test]
    fn display_is_decimal() {
        assert_eq!(BigInteger::from_i32(-12345).to_string(), "-12345");
        assert_eq!(format!("{}", BigInteger::from_u32(42)), "42");
    }

    #[test]
    fn to_str_radix_matches_native() {
        // 對照原生格式化（正數，各原生支援的 radix）
        let vals = [0u128, 1, 255, 0xDEAD_BEEF, u128::MAX];
        for &v in &vals {
            let n = BigInteger::from_u128(v);
            assert_eq!(n.to_str_radix(10), v.to_string(), "{v} dec");
            assert_eq!(n.to_str_radix(16), format!("{v:x}"), "{v} hex");
            assert_eq!(n.to_str_radix(2), format!("{v:b}"), "{v} bin");
            assert_eq!(n.to_str_radix(8), format!("{v:o}"), "{v} oct");
        }
    }

    #[test]
    fn to_from_str_radix_roundtrip() {
        // to_str_radix ↔ from_str_radix 來回，涵蓋各符號、i128::MIN、各 radix（含 36）
        let vals = [0i128, 1, -1, 255, -256, 123456789, -987654321, i128::MAX, i128::MIN];
        for &v in &vals {
            let n = BigInteger::from_i128(v);
            for radix in [2u32, 8, 10, 16, 36] {
                let s = n.to_str_radix(radix);
                let back = BigInteger::from_str_radix(&s, radix).unwrap();
                assert_eq!(back, n, "v={v} radix={radix}");
            }
        }
    }

    #[test]
    fn rem_euclid_matches_native() {
        // 對照原生 i128::rem_euclid，涵蓋各種符號
        let vals = [0i128, 1, -1, 7, -7, 100, -100, 3, -3, 12345, -12345];
        for &a in &vals {
            for &b in &vals {
                if b == 0 {
                    continue;
                }
                let got = BigInteger::from_i128(a).rem_euclid(&BigInteger::from_i128(b));
                assert_eq!(got, BigInteger::from_i128(a.rem_euclid(b)), "{a} rem_euclid {b}");
            }
        }
    }

    #[test]
    fn rem_euclid_is_non_negative() {
        // 結果永遠非負（落在 [0, |other|)），且負除數也適用
        assert_eq!(BigInteger::from_i32(-7).rem_euclid(&BigInteger::from_i32(3)), BigInteger::from_i32(2));
        assert_eq!(BigInteger::from_i32(-7).rem_euclid(&BigInteger::from_i32(-3)), BigInteger::from_i32(2));
        assert_eq!(BigInteger::from_i32(7).rem_euclid(&BigInteger::from_i32(-3)), BigInteger::from_i32(1));
        assert!(BigInteger::from_i32(-100).rem_euclid(&BigInteger::from_i32(7)).sign() >= 0);
    }

    #[test]
    #[should_panic(expected = "divisor of zero")]
    fn rem_euclid_by_zero_panics() {
        let _ = BigInteger::from_i32(5).rem_euclid(&BigInteger::from_i32(0));
    }

    #[test]
    fn gcd_basic() {
        assert_eq!(BigInteger::from_i32(30).gcd(&BigInteger::from_i32(18)), BigInteger::from_i32(6));
        assert_eq!(BigInteger::from_i32(-12).gcd(&BigInteger::from_i32(18)), BigInteger::from_i32(6)); // 負看絕對值
        assert_eq!(BigInteger::from_i32(17).gcd(&BigInteger::from_i32(5)), BigInteger::from_i32(1)); // 互質
        assert_eq!(BigInteger::from_i32(0).gcd(&BigInteger::from_i32(5)), BigInteger::from_i32(5));
        assert_eq!(BigInteger::from_i32(5).gcd(&BigInteger::from_i32(0)), BigInteger::from_i32(5));
        assert_eq!(BigInteger::from_i32(0).gcd(&BigInteger::from_i32(0)), BigInteger::from_i32(0));
    }

    #[test]
    fn gcd_matches_native() {
        fn gcd_i128(mut a: i128, mut b: i128) -> i128 {
            (a, b) = (a.abs(), b.abs());
            while b != 0 {
                (a, b) = (b, a % b);
            }
            a
        }
        let vals = [0i128, 1, -1, 12, -12, 18, 30, 100, 17, 35, -49, 1 << 40];
        for &a in &vals {
            for &b in &vals {
                assert_eq!(
                    BigInteger::from_i128(a).gcd(&BigInteger::from_i128(b)),
                    BigInteger::from_i128(gcd_i128(a, b)),
                    "gcd({a},{b})"
                );
            }
        }
    }

    #[test]
    fn extended_gcd_basic() {
        // gcd(30, 18) = 6，且 30·x ≡ 6 (mod 18)
        let (g, x) = extended_gcd(&BigInteger::from_i32(30), &BigInteger::from_i32(18));
        assert_eq!(g, BigInteger::from_i32(6));
        let m = BigInteger::from_i32(18);
        assert_eq!((&BigInteger::from_i32(30) * &x).rem_euclid(&m), g.rem_euclid(&m));

        // 互質：gcd = 1，x 為反元素（3·x ≡ 1 mod 7 → x = 5）
        let (g, x) = extended_gcd(&BigInteger::from_i32(3), &BigInteger::from_i32(7));
        assert_eq!(g, BigInteger::from_i32(1));
        assert_eq!(
            (&BigInteger::from_i32(3) * &x).rem_euclid(&BigInteger::from_i32(7)),
            BigInteger::from_i32(1)
        );
    }

    #[test]
    fn extended_gcd_matches_native() {
        fn gcd_i128(mut a: i128, mut b: i128) -> i128 {
            a = a.abs();
            b = b.abs();
            while b != 0 {
                let t = b;
                b = a % b;
                a = t;
            }
            a
        }
        let vals = [1i128, 2, 3, 6, 12, 30, 18, 100, 17, 35, 49, 128];
        for &a in &vals {
            for &b in &vals {
                let (g, x) = extended_gcd(&BigInteger::from_i128(a), &BigInteger::from_i128(b));
                assert_eq!(g, BigInteger::from_i128(gcd_i128(a, b)), "gcd({a},{b})");
                // Bézout 同餘：a·x ≡ gcd (mod b)
                let m = BigInteger::from_i128(b);
                let ax = &BigInteger::from_i128(a) * &x;
                assert_eq!(ax.rem_euclid(&m), g.rem_euclid(&m), "bezout({a},{b})");
            }
        }
    }

    #[test]
    fn mod_inverse_basic() {
        // 3⁻¹ ≡ 5 (mod 7)
        assert_eq!(
            BigInteger::from_i32(3).mod_inverse(&BigInteger::from_i32(7)),
            Some(BigInteger::from_i32(5))
        );
        // 不互質 → None
        assert_eq!(BigInteger::from_i32(4).mod_inverse(&BigInteger::from_i32(6)), None);
        // 負 self 先約簡：-3 ≡ 4 (mod 7)，其反元素驗 (-3)·inv ≡ 1
        let m = BigInteger::from_i32(7);
        let inv = BigInteger::from_i32(-3).mod_inverse(&m).unwrap();
        assert_eq!((&BigInteger::from_i32(-3) * &inv).rem_euclid(&m), BigInteger::from_i32(1));
    }

    #[test]
    fn mod_inverse_matches_reference() {
        fn gcd_i128(mut a: i128, mut b: i128) -> i128 {
            while b != 0 {
                (a, b) = (b, a % b);
            }
            a.abs()
        }
        let moduli = [2i128, 3, 7, 13, 26, 97, 100];
        for &m in &moduli {
            let big_m = BigInteger::from_i128(m);
            for a in 1..m {
                let big_a = BigInteger::from_i128(a);
                match big_a.mod_inverse(&big_m) {
                    Some(inv) => {
                        // 互質：a·inv ≡ 1 (mod m)，且 inv ∈ [0, m)
                        assert_eq!(
                            (&big_a * &inv).rem_euclid(&big_m),
                            BigInteger::from_i32(1),
                            "{a}⁻¹ mod {m}"
                        );
                        assert!(inv.sign() >= 0 && inv < big_m, "{a}⁻¹ mod {m} 超出 [0,m)");
                    }
                    None => {
                        // None：a 與 m 不互質
                        assert_ne!(gcd_i128(a, m), 1, "{a} mod {m} 其實互質，不該回 None");
                    }
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "modulus must be positive")]
    fn mod_inverse_non_positive_modulus_panics() {
        let _ = BigInteger::from_i32(3).mod_inverse(&BigInteger::from_i32(0));
    }

    #[test]
    fn mod_pow_basic() {
        let seven = BigInteger::from_i32(7);
        // 3^4 = 81 ≡ 4 (mod 7)
        assert_eq!(BigInteger::from_i32(3).mod_pow(&BigInteger::from_i32(4), &seven), BigInteger::from_i32(4));
        // a^0 = 1
        assert_eq!(BigInteger::from_i32(5).mod_pow(&BigInteger::from_i32(0), &seven), BigInteger::from_i32(1));
        // mod 1 = 0
        assert_eq!(BigInteger::from_i32(5).mod_pow(&BigInteger::from_i32(3), &BigInteger::from_i32(1)), BigInteger::from_i32(0));
        // 0^e = 0（e > 0）
        assert_eq!(BigInteger::from_i32(0).mod_pow(&BigInteger::from_i32(5), &seven), BigInteger::from_i32(0));
        // 負指數：3^(-1) ≡ 5 (mod 7)
        assert_eq!(BigInteger::from_i32(3).mod_pow(&BigInteger::from_i32(-1), &seven), BigInteger::from_i32(5));
    }

    #[test]
    fn mod_pow_matches_native() {
        fn modpow_u128(mut base: u128, mut exp: u128, m: u128) -> u128 {
            let mut r = 1u128 % m;
            base %= m;
            while exp > 0 {
                if exp & 1 == 1 {
                    r = r * base % m;
                }
                base = base * base % m;
                exp >>= 1;
            }
            r
        }
        let bases = [0u128, 1, 2, 3, 7, 10, 12345];
        let exps = [0u128, 1, 2, 5, 10, 100];
        let mods = [1u128, 2, 7, 13, 1000, 65537]; // 小 mod，原生中間值不溢位
        for &b in &bases {
            for &ex in &exps {
                for &m in &mods {
                    let got = BigInteger::from_u128(b)
                        .mod_pow(&BigInteger::from_u128(ex), &BigInteger::from_u128(m));
                    assert_eq!(got, BigInteger::from_u128(modpow_u128(b, ex, m)), "{b}^{ex} mod {m}");
                }
            }
        }
    }

    #[test]
    fn mod_pow_fermat_little_theorem() {
        // 費馬小定理：p 質數、a 不被 p 整除 → a^(p-1) ≡ 1 (mod p)
        let p = BigInteger::from_i32(65537); // Fermat 質數 2^16+1，指數 65536 = 16 次平方
        let a = BigInteger::from_i32(12345);
        let e = &p - &BigInteger::from_u32(1);
        assert_eq!(a.mod_pow(&e, &p), BigInteger::from_u32(1));
    }

    #[test]
    #[should_panic(expected = "modulus must be positive")]
    fn mod_pow_non_positive_modulus_panics() {
        let _ = BigInteger::from_i32(3).mod_pow(&BigInteger::from_i32(2), &BigInteger::from_i32(0));
    }

    #[test]
    fn div_rem_zero_dividend() {
        let (q, r) = BigInteger::from_i32(0).div_rem(&BigInteger::from_i32(7));
        assert_eq!(q, BigInteger::from_i32(0));
        assert_eq!(r, BigInteger::from_i32(0));
    }

    #[test]
    #[should_panic(expected = "divide by zero")]
    fn div_by_zero_panics() {
        let _ = &BigInteger::from_i32(5) / &BigInteger::from_i32(0);
    }

    #[test]
    #[should_panic(expected = "divide by zero")]
    fn rem_by_zero_panics() {
        let _ = &BigInteger::from_i32(5) % &BigInteger::from_i32(0);
    }

    #[test]
    fn add_operator_same_sign() {
        assert_eq!(&BigInteger::from_i32(5) + &BigInteger::from_i32(3), BigInteger::from_i32(8));
        assert_eq!(&BigInteger::from_i32(-5) + &BigInteger::from_i32(-3), BigInteger::from_i32(-8));
    }

    #[test]
    fn add_operator_different_signs() {
        assert_eq!(&BigInteger::from_i32(5) + &BigInteger::from_i32(-3), BigInteger::from_i32(2));
        assert_eq!(&BigInteger::from_i32(-5) + &BigInteger::from_i32(3), BigInteger::from_i32(-2));
        assert_eq!(&BigInteger::from_i32(3) + &BigInteger::from_i32(-5), BigInteger::from_i32(-2));
        assert_eq!(&BigInteger::from_i32(5) + &BigInteger::from_i32(-5), BigInteger::from_i32(0));
    }

    #[test]
    fn add_operator_with_zero() {
        assert_eq!(&BigInteger::from_i32(0) + &BigInteger::from_i32(7), BigInteger::from_i32(7));
        assert_eq!(&BigInteger::from_i32(7) + &BigInteger::from_i32(0), BigInteger::from_i32(7));
    }

    #[test]
    fn sub_operator_basic() {
        assert_eq!(&BigInteger::from_i32(8) - &BigInteger::from_i32(3), BigInteger::from_i32(5));
        assert_eq!(&BigInteger::from_i32(3) - &BigInteger::from_i32(8), BigInteger::from_i32(-5));
        assert_eq!(&BigInteger::from_i32(5) - &BigInteger::from_i32(-3), BigInteger::from_i32(8));
        assert_eq!(&BigInteger::from_i32(-5) - &BigInteger::from_i32(3), BigInteger::from_i32(-8));
        assert_eq!(&BigInteger::from_i32(5) - &BigInteger::from_i32(5), BigInteger::from_i32(0));
    }

    #[test]
    fn add_matches_i128_reference() {
        // 用原生 i128 算和當獨立參照，涵蓋各種符號與大小組合
        let vals = [0i64, 1, -1, 5, -5, 255, -256, 1 << 32, -(1 << 32), i64::MAX, i64::MIN];
        for &a in &vals {
            for &b in &vals {
                let got = &BigInteger::from_i64(a) + &BigInteger::from_i64(b);
                let want = BigInteger::from_i128(a as i128 + b as i128);
                assert_eq!(got, want, "{a} + {b}");
            }
        }
    }

    #[test]
    fn sub_matches_i128_reference() {
        let vals = [0i64, 1, -1, 5, -5, 255, -256, 1 << 32, -(1 << 32), i64::MAX, i64::MIN];
        for &a in &vals {
            for &b in &vals {
                let got = &BigInteger::from_i64(a) - &BigInteger::from_i64(b);
                let want = BigInteger::from_i128(a as i128 - b as i128);
                assert_eq!(got, want, "{a} - {b}");
            }
        }
    }

    #[test]
    fn add_commutative_and_sub_relation() {
        let a = BigInteger::from_i64(123456789012);
        let b = BigInteger::from_i64(-98765432109);
        assert_eq!(&a + &b, &b + &a); // a + b == b + a
        assert_eq!(&a - &b, -(&b - &a)); // a - b == -(b - a)
    }

    #[test]
    fn try_into_primitive_ok() {
        assert_eq!(u32::try_from(&BigInteger::from_u32(255)), Ok(255u32));
        assert_eq!(i32::try_from(&BigInteger::from_i32(-5)), Ok(-5i32));
        assert_eq!(u8::try_from(&BigInteger::from_u32(200)), Ok(200u8));
        assert_eq!(i8::try_from(&BigInteger::from_i32(-128)), Ok(-128i8)); // i8::MIN
        assert_eq!(i8::try_from(&BigInteger::from_i32(127)), Ok(127i8)); // i8::MAX
        assert_eq!(u128::try_from(&BigInteger::from_u128(u128::MAX)), Ok(u128::MAX));
        assert_eq!(i128::try_from(&BigInteger::from_i128(i128::MIN)), Ok(i128::MIN));
        assert_eq!(i128::try_from(&BigInteger::from_i128(i128::MAX)), Ok(i128::MAX));
        // TryInto 也可用（TryFrom 的對偶）
        let x: u64 = (&BigInteger::from_u64(12345)).try_into().unwrap();
        assert_eq!(x, 12345);
    }

    #[test]
    fn try_into_primitive_out_of_range() {
        assert!(u8::try_from(&BigInteger::from_u32(256)).is_err()); // 太大
        assert!(i8::try_from(&BigInteger::from_i32(200)).is_err()); // > i8::MAX
        assert!(i8::try_from(&BigInteger::from_i32(-129)).is_err()); // < i8::MIN
        assert!(u32::try_from(&BigInteger::from_i32(-1)).is_err()); // 負數轉無號
        // 超出 u128 / i128
        let two_128 = &BigInteger::from_u128(u128::MAX) + &BigInteger::from_u32(1); // 2^128
        assert!(u128::try_from(&two_128).is_err());
        assert!(i128::try_from(&two_128).is_err());
        // 2^127：放不進 i128，但放得進 u128
        let two_127 = &BigInteger::from_i128(i128::MAX) + &BigInteger::from_u32(1);
        assert!(i128::try_from(&two_127).is_err());
        assert_eq!(u128::try_from(&two_127), Ok(1u128 << 127));
    }

    #[test]
    fn try_into_primitive_matches_native_bounds() {
        // 邊界對照原生 i64::try_from(i128) / u64::try_from(u128)
        let vals = [
            0i128, 1, -1, i64::MAX as i128, i64::MAX as i128 + 1,
            i64::MIN as i128, i64::MIN as i128 - 1,
        ];
        for &v in &vals {
            let big = BigInteger::from_i128(v);
            assert_eq!(i64::try_from(&big).ok(), i64::try_from(v).ok(), "i64 {v}");
        }
        let uvals = [0u128, 1, u64::MAX as u128, u64::MAX as u128 + 1];
        for &v in &uvals {
            let big = BigInteger::from_u128(v);
            assert_eq!(u64::try_from(&big).ok(), u64::try_from(v).ok(), "u64 {v}");
        }
    }

    #[test]
    fn from_trait_matches_constructors() {
        // From / into 與既有建構函式結果一致，涵蓋全部寬度
        assert_eq!(BigInteger::from(5u8), BigInteger::from_u8(5));
        assert_eq!(BigInteger::from(5u16), BigInteger::from_u16(5));
        assert_eq!(BigInteger::from(5u32), BigInteger::from_u32(5));
        assert_eq!(BigInteger::from(u64::MAX), BigInteger::from_u64(u64::MAX));
        assert_eq!(BigInteger::from(u128::MAX), BigInteger::from_u128(u128::MAX));
        assert_eq!(BigInteger::from(-5i8), BigInteger::from_i8(-5));
        assert_eq!(BigInteger::from(-5i16), BigInteger::from_i16(-5));
        assert_eq!(BigInteger::from(i32::MIN), BigInteger::from_i32(i32::MIN));
        assert_eq!(BigInteger::from(i64::MIN), BigInteger::from_i64(i64::MIN));
        assert_eq!(BigInteger::from(i128::MIN), BigInteger::from_i128(i128::MIN));
        // Into 亦可用（型別標註觸發）
        let a: BigInteger = 42u32.into();
        assert_eq!(a, BigInteger::from_u32(42));
    }

    #[test]
    fn add_multi_word_carry() {
        // (2^64 - 1) + 1 = 2^64
        let a = BigInteger::from_u64(u64::MAX);
        let one = BigInteger::from_u32(1);
        assert_eq!(&a + &one, BigInteger::from_i128(u64::MAX as i128 + 1));
    }

    #[test]
    fn eq_same_value_from_different_sources() {
        // 同一個數、不同建構路徑，應相等
        assert_eq!(BigInteger::from_i32(128), BigInteger::from_bytes_be(&[0x00, 0x80]));
        assert_eq!(BigInteger::from_u64(0), BigInteger::from_i32(0));
    }

    #[test]
    fn eq_distinguishes_sign_and_magnitude() {
        assert_ne!(BigInteger::from_i32(5), BigInteger::from_i32(-5)); // 同 magnitude、異號
        assert_ne!(BigInteger::from_i32(5), BigInteger::from_i32(6)); // 同號、異 magnitude
    }

    #[test]
    fn from_u32_positive() {
        let n = BigInteger::from_u32(5);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn from_u32_max() {
        let n = BigInteger::from_u32(u32::MAX);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![u32::MAX]);
    }

    #[test]
    fn from_u16_zero_and_max() {
        let zero = BigInteger::from_u16(0);
        assert_eq!(zero.sign, 0);
        assert!(zero.magnitude.is_empty());

        let max = BigInteger::from_u16(u16::MAX);
        assert_eq!(max.sign, 1);
        assert_eq!(max.magnitude.to_vec(), vec![u32::from(u16::MAX)]);
    }

    #[test]
    fn from_u8_zero_and_max() {
        let zero = BigInteger::from_u8(0);
        assert_eq!(zero.sign, 0);
        assert!(zero.magnitude.is_empty());

        let max = BigInteger::from_u8(u8::MAX);
        assert_eq!(max.sign, 1);
        assert_eq!(max.magnitude.to_vec(), vec![u32::from(u8::MAX)]);
    }

    #[test]
    fn from_u64_zero() {
        let n = BigInteger::from_u64(0);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn from_u64_single_word() {
        // Fits in one word -> no leading zero word.
        let n = BigInteger::from_u64(5);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn from_u64_two_words() {
        // 0x0000_0001_0000_0002 -> [1, 2] big-endian.
        let n = BigInteger::from_u64((1 << 32) | 2);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![1, 2]);
    }

    #[test]
    fn from_u64_max() {
        let n = BigInteger::from_u64(u64::MAX);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![u32::MAX, u32::MAX]);
    }

    #[test]
    fn from_i32_zero() {
        let n = BigInteger::from_i32(0);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn from_i32_positive() {
        let n = BigInteger::from_i32(5);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn from_i32_negative() {
        let n = BigInteger::from_i32(-5);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn from_i32_min() {
        // -i32::MIN would overflow; magnitude is 2^31.
        let n = BigInteger::from_i32(i32::MIN);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![1 << 31]);
    }

    #[test]
    fn from_i32_max() {
        let n = BigInteger::from_i32(i32::MAX);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![i32::MAX as u32]);
    }

    #[test]
    fn from_i16_negative_and_min() {
        let neg = BigInteger::from_i16(-5);
        assert_eq!(neg.sign, -1);
        assert_eq!(neg.magnitude.to_vec(), vec![5]);

        let min = BigInteger::from_i16(i16::MIN);
        assert_eq!(min.sign, -1);
        assert_eq!(min.magnitude.to_vec(), vec![i16::MIN.unsigned_abs() as u32]);
    }

    #[test]
    fn from_i8_negative_and_min() {
        let neg = BigInteger::from_i8(-5);
        assert_eq!(neg.sign, -1);
        assert_eq!(neg.magnitude.to_vec(), vec![5]);

        let min = BigInteger::from_i8(i8::MIN);
        assert_eq!(min.sign, -1);
        assert_eq!(min.magnitude.to_vec(), vec![i8::MIN.unsigned_abs() as u32]);
    }

    #[test]
    fn from_i64_negative_two_words() {
        let n = BigInteger::from_i64(-((1i64 << 32) | 2));
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![1, 2]);
    }

    #[test]
    fn from_i64_min() {
        // -i64::MIN would overflow; magnitude is 2^63 -> high word 0x8000_0000.
        let n = BigInteger::from_i64(i64::MIN);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![1 << 31, 0]);
    }

    #[test]
    fn from_i128_negative_and_min() {
        let neg = BigInteger::from_i128(-5);
        assert_eq!(neg.sign, -1);
        assert_eq!(neg.magnitude.to_vec(), vec![5]);

        // magnitude of i128::MIN is 2^127 -> top word 0x8000_0000, rest zero.
        let min = BigInteger::from_i128(i128::MIN);
        assert_eq!(min.sign, -1);
        assert_eq!(min.magnitude.to_vec(), vec![1 << 31, 0, 0, 0]);
    }

    #[test]
    fn from_u128_zero() {
        let n = BigInteger::from_u128(0);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn from_u128_single_word() {
        let n = BigInteger::from_u128(5);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn from_u128_strips_leading_zero_words() {
        // 0x0000_0000_0000_0003_0000_0000_0000_0004
        // = word3<<96 | ... ; top two words are zero and must be dropped.
        let value = (3u128 << 64) | 4;
        let n = BigInteger::from_u128(value);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![3, 0, 4]);
    }

    #[test]
    fn from_u128_max() {
        let n = BigInteger::from_u128(u128::MAX);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![u32::MAX, u32::MAX, u32::MAX, u32::MAX]);
    }

    #[test]
    fn make_magnitude_be_empty() {
        assert_eq!(make_magnitude_be(&[]), Vec::<u32>::new());
    }

    #[test]
    fn make_magnitude_be_all_zero() {
        // 全零位元組視同 0，得到空 magnitude
        assert_eq!(make_magnitude_be(&[0, 0, 0]), Vec::<u32>::new());
    }

    #[test]
    fn make_magnitude_be_single_byte() {
        assert_eq!(make_magnitude_be(&[0x05]), vec![0x05]);
    }

    #[test]
    fn make_magnitude_be_strips_leading_zeros() {
        // 前導零 + 殘塊：只保留有效位元組
        assert_eq!(make_magnitude_be(&[0, 0, 0xAA, 0xBB]), vec![0xAABB]);
    }

    #[test]
    fn make_magnitude_be_partial_then_full_word() {
        // 殘塊(AABB) + 一個滿字(CCDDEEFF)
        let buffer = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(make_magnitude_be(&buffer), vec![0x0000_AABB, 0xCCDD_EEFF]);
    }

    #[test]
    fn make_magnitude_be_exact_word() {
        // 剛好 4 位元組，單一滿字
        assert_eq!(make_magnitude_be(&[1, 2, 3, 4]), vec![0x0102_0304]);
    }

    #[test]
    fn make_magnitude_be_keeps_interior_zero() {
        // 中間的零位元組必須保留，只有最高位端的零才剝除
        let buffer = [0x01, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(make_magnitude_be(&buffer), vec![0x01, 0x0000_0000]);
    }

    #[test]
    fn make_magnitude_le_empty() {
        assert_eq!(make_magnitude_le(&[]), Vec::<u32>::new());
    }

    #[test]
    fn make_magnitude_le_all_zero() {
        // 全零位元組視同 0，得到空 magnitude
        assert_eq!(make_magnitude_le(&[0, 0, 0]), Vec::<u32>::new());
    }

    #[test]
    fn make_magnitude_le_single_byte() {
        assert_eq!(make_magnitude_le(&[0x05]), vec![0x05]);
    }

    #[test]
    fn make_magnitude_le_strips_trailing_zeros() {
        // little-endian 的無意義零在尾端；[00,01] 代表 0x0100
        assert_eq!(make_magnitude_le(&[0x00, 0x01]), vec![0x0100]);
    }

    #[test]
    fn make_magnitude_le_partial_high_word() {
        // 0xAABBCCDDEEFF 的 LE 表示；最高位字 (AABB) 為殘塊
        let buffer = [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA];
        assert_eq!(make_magnitude_le(&buffer), vec![0x0000_AABB, 0xCCDD_EEFF]);
    }

    #[test]
    fn make_magnitude_le_two_words() {
        // 2^32：LE 為 [00,00,00,00,01]，magnitude 為 [1, 0]
        let buffer = [0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(make_magnitude_le(&buffer), vec![1, 0]);
    }

    #[test]
    fn make_magnitude_le_matches_be_reversed() {
        // 同一個數：BE 輸入反轉即為其 LE 輸入，兩者 magnitude 必須相同
        let be = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let le: Vec<u8> = be.iter().rev().copied().collect();
        assert_eq!(make_magnitude_be(&be), make_magnitude_le(&le));
    }

    #[test]
    fn make_magnitude_be_negative_minus_one() {
        // 0xFF = -1，絕對值 magnitude 為 [1]
        assert_eq!(make_magnitude_be_negative(&[0xFF]), vec![1]);
        // 多位元組的 -1：0xFFFF 仍是 -1
        assert_eq!(make_magnitude_be_negative(&[0xFF, 0xFF]), vec![1]);
    }

    #[test]
    fn make_magnitude_be_negative_minus_128() {
        // 0x80 = -128
        assert_eq!(make_magnitude_be_negative(&[0x80]), vec![128]);
    }

    #[test]
    fn make_magnitude_be_negative_carry_propagates() {
        // 0xFF0000 = -65536；反相加 1 的進位會傳到新的高位字
        assert_eq!(make_magnitude_be_negative(&[0xFF, 0x00, 0x00]), vec![0x0001_0000]);
    }

    #[test]
    fn make_magnitude_be_negative_strips_sign_extension() {
        // 0xFFFFFF80 = -128，前導的 0xFF 符號延伸不影響絕對值
        assert_eq!(
            make_magnitude_be_negative(&[0xFF, 0xFF, 0xFF, 0x80]),
            vec![128]
        );
    }

    #[test]
    fn make_magnitude_le_negative_matches_be_reversed() {
        // 對同一個負數：BE 輸入反轉即為 LE 輸入，兩者絕對值 magnitude 必須相同
        let be = [0xFF, 0x00, 0x00]; // -65536
        let le: Vec<u8> = be.iter().rev().copied().collect();
        assert_eq!(
            make_magnitude_be_negative(&be),
            make_magnitude_le_negative(&le)
        );
    }

    #[test]
    fn make_magnitude_le_negative_minus_128() {
        // LE 的 0x80（單一位元組）= -128
        assert_eq!(make_magnitude_le_negative(&[0x80]), vec![128]);
    }

    #[test]
    fn from_bytes_be_empty_is_zero() {
        let n = BigInteger::from_bytes_be(&[]);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn from_bytes_be_zero() {
        let n = BigInteger::from_bytes_be(&[0x00, 0x00]);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn from_bytes_be_positive() {
        let n = BigInteger::from_bytes_be(&[0x05]);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn from_bytes_be_leading_zero_forces_positive() {
        // 0x80 單獨會被當負數；前綴一個 0x00 才是正的 128
        let n = BigInteger::from_bytes_be(&[0x00, 0x80]);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![128]);
    }

    #[test]
    fn from_bytes_be_minus_one() {
        let n = BigInteger::from_bytes_be(&[0xFF]);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![1]);
    }

    #[test]
    fn from_bytes_be_minus_128() {
        let n = BigInteger::from_bytes_be(&[0x80]);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![128]);
    }

    #[test]
    fn from_bytes_be_matches_from_i32() {
        // 用 i32 的 big-endian 位元組重建，應與 from_i32 結果一致
        for value in [0, 1, -1, 5, -5, 255, -255, 65536, -65536, i32::MAX, i32::MIN] {
            let n = BigInteger::from_bytes_be(&value.to_be_bytes());
            let expected = BigInteger::from_i32(value);
            assert_eq!(n.sign, expected.sign, "sign mismatch for {value}");
            assert_eq!(n.magnitude, expected.magnitude, "magnitude mismatch for {value}");
        }
    }

    #[test]
    fn from_bytes_le_empty_is_zero() {
        let n = BigInteger::from_bytes_le(&[]);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn from_bytes_le_leading_zero_forces_positive() {
        // LE：符號在尾端。[0x80, 0x00] 尾端最高位為 0 → 正的 128
        let n = BigInteger::from_bytes_le(&[0x80, 0x00]);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![128]);
    }

    #[test]
    fn from_bytes_le_minus_one() {
        let n = BigInteger::from_bytes_le(&[0xFF]);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![1]);
    }

    #[test]
    fn from_bytes_le_matches_from_i32() {
        // 用 i32 的 little-endian 位元組重建，應與 from_i32 結果一致
        for value in [0, 1, -1, 5, -5, 255, -255, 65536, -65536, i32::MAX, i32::MIN] {
            let n = BigInteger::from_bytes_le(&value.to_le_bytes());
            let expected = BigInteger::from_i32(value);
            assert_eq!(n.sign, expected.sign, "sign mismatch for {value}");
            assert_eq!(n.magnitude, expected.magnitude, "magnitude mismatch for {value}");
        }
    }

    #[test]
    fn from_bytes_le_matches_be_reversed() {
        // 同一個數：BE 位元組反轉即為 LE 位元組，兩者結果必須相同
        let be = [0xFF, 0x00, 0x00]; // -65536
        let le: Vec<u8> = be.iter().rev().copied().collect();
        let a = BigInteger::from_bytes_be(&be);
        let b = BigInteger::from_bytes_le(&le);
        assert_eq!(a.sign, b.sign);
        assert_eq!(a.magnitude, b.magnitude);
    }
}