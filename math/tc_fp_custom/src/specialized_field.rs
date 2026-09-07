//! 其餘 SEC 質數曲線共用的靜態 u32-limb 欄位骨架。
//!
//! 每條曲線仍以獨立 [`PrimeFieldSpec`] 提供質數與參數；乘積以
//! `p = 2^m - c` 的 Solinas 關係反覆摺疊，不經 Montgomery 表示。共用骨架
//! 只收掉尺寸與搬運程式碼，實際模數與 `a = 0`／`a = -3` 決策仍在型別上。

use core::fmt::Debug;
use core::marker::PhantomData;
use core::ops::{Add, Mul, Neg, Shr, Sub};

use tc_bigint::{ArrayEncoding, BitOps, FromPrimitive, NumRef, modular::mod_odd_inverse};
use tc_constant_time::{Choice, ConstantTimeEq, ConstantTimeOrd};
use tc_ec_core::{FieldElement, PrimeFieldElement};

const MAX_LIMBS: usize = 17;
const MAX_WIDE_LIMBS: usize = MAX_LIMBS * 2;
pub(crate) const MAX_INTEGER_LIMBS: usize = 18;

/// 特化曲線整數所需的最小能力集合。
#[doc(hidden)]
pub trait CustomInteger:
    ArrayEncoding
    + BitOps<Output = Self>
    + FromPrimitive
    + NumRef
    + Clone
    + Debug
    + Ord
    + Shr<usize, Output = Self>
{
}

impl<T> CustomInteger for T where
    T: ArrayEncoding
        + BitOps<Output = T>
        + FromPrimitive
        + NumRef
        + Clone
        + Debug
        + Ord
        + Shr<usize, Output = T>
{
}

/// `a` 在 Jacobian 倍點公式中的可用特化。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum AForm {
    /// Koblitz 質數曲線的 `a = 0`。
    Zero,
    /// SEC 隨機曲線常見的 `a = -3 mod p`。
    MinusThree,
}

/// 編譯期選定的 Solinas 約簡形狀。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum ReductionKind {
    /// General Solinas folding for SM2's sparse modulus complement.
    Sm2,
    /// P-128 的 `2^128 - 2^97 - 1` 展開式。
    P128,
    /// `c` 可放入 u64 的 word-aligned 質數。
    SmallComplement(u64),
    /// P-384 的 bc 展開式。
    P384,
    /// P-192 的 bc 展開式。
    P192R1,
    /// P-224 的 bc 展開式。
    P224R1,
    /// P-521 的 `2^521 - 1` Mersenne 摺疊。
    Mersenne521,
}

/// 一條編譯期已知質數曲線的欄位與群參數。
#[doc(hidden)]
pub trait PrimeFieldSpec<const N: usize>:
    Clone + Copy + Debug + Eq + Send + Sync + 'static
{
    /// 座標與標量使用的固定寬整數。
    type Integer: CustomInteger;

    /// 曲線名稱。
    const NAME: &'static str;
    /// 質數有效位元數。
    const BITS: usize;
    /// SEC1 單一座標寬度。
    const BYTES: usize;
    /// 體域質數。
    const P: [u32; N];
    /// 曲線係數 `a`。
    const A: [u32; N];
    /// 曲線係數 `b`。
    const B: [u32; N];
    /// 基點子群階。
    const ORDER: [u32; MAX_INTEGER_LIMBS];
    /// 標準生成點 X。
    const GX: [u32; N];
    /// 標準生成點 Y。
    const GY: [u32; N];
    /// 倍點公式特化。
    const A_FORM: AForm;
    /// 質數對應的約簡核心。
    const REDUCTION: ReductionKind;
}

/// 編譯期解析十六進位常數為 little-endian u32 limbs。
#[doc(hidden)]
pub const fn hex_words<const N: usize>(hex: &str) -> [u32; N] {
    let bytes = hex.as_bytes();
    let mut result = [0_u32; N];
    let mut source = bytes.len();
    let mut nibble = 0_usize;
    while source > 0 {
        source -= 1;
        let byte = bytes[source];
        let value = if byte >= b'0' && byte <= b'9' {
            byte - b'0'
        } else if byte >= b'A' && byte <= b'F' {
            byte - b'A' + 10
        } else if byte >= b'a' && byte <= b'f' {
            byte - b'a' + 10
        } else {
            panic!("invalid hexadecimal curve constant")
        };
        let word = nibble / 8;
        assert!(word < N, "curve constant exceeds its limb width");
        result[word] |= (value as u32) << ((nibble % 8) * 4);
        nibble += 1;
    }
    result
}

/// 靜態質數體的底層運算入口。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct SpecializedField<S, const N: usize>(PhantomData<S>);

impl<S: PrimeFieldSpec<N>, const N: usize> SpecializedField<S, N> {
    /// 體域質數。
    pub const P: [u32; N] = S::P;

    /// 模數內加法。
    pub fn add(left: &[u32; N], right: &[u32; N]) -> [u32; N] {
        let (result, carry) = add_words(left, right);
        if carry {
            let mut wide = [0_u32; MAX_WIDE_LIMBS];
            wide[..N].copy_from_slice(&result);
            wide[N] = 1;
            reduce_solinas::<S, N>(&wide)
        } else if gte(&result, &S::P).unwrap_u8() != 0 {
            sub_words(&result, &S::P).0
        } else {
            result
        }
    }

    /// 模數內減法。
    pub fn subtract(left: &[u32; N], right: &[u32; N]) -> [u32; N] {
        let (mut result, borrow) = sub_words(left, right);
        if borrow {
            result = add_words(&result, &S::P).0;
        }
        result
    }

    /// 模數內倍增。
    pub fn twice(value: &[u32; N]) -> [u32; N] {
        Self::add(value, value)
    }

    /// 加法反元素。
    pub fn negate(value: &[u32; N]) -> [u32; N] {
        if is_zero(value) {
            [0; N]
        } else {
            sub_words(&S::P, value).0
        }
    }

    /// 模數內乘法。
    pub fn multiply(left: &[u32; N], right: &[u32; N]) -> [u32; N] {
        reduce::<S, N>(&multiply_wide(left, right))
    }

    /// 模數內平方。
    pub fn square(value: &[u32; N]) -> [u32; N] {
        reduce::<S, N>(&multiply_wide(value, value))
    }

    /// 連續平方。
    pub fn square_n(value: &[u32; N], count: usize) -> [u32; N] {
        let mut result = *value;
        for _ in 0..count {
            result = Self::square(&result);
        }
        result
    }

    /// 固定步數 odd-modulus safegcd 反元素。
    pub fn invert(value: &[u32; N]) -> Option<[u32; N]> {
        let mut result = [0_u32; N];
        mod_odd_inverse(&S::P, value, &mut result).then_some(result)
    }
}

/// 靜態 u32-limb 質數體元素。
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[doc(hidden)]
pub struct SpecializedFieldElement<S, const N: usize>
where
    S: PrimeFieldSpec<N>,
{
    words: [u32; N],
    marker: PhantomData<S>,
}

impl<S: PrimeFieldSpec<N>, const N: usize> SpecializedFieldElement<S, N> {
    /// 加法單位元。
    pub const ZERO: Self = Self::new_unchecked([0; N]);
    /// 乘法單位元。
    pub const ONE: Self = {
        let mut words = [0_u32; N];
        words[0] = 1;
        Self::new_unchecked(words)
    };

    pub(crate) const fn new_unchecked(words: [u32; N]) -> Self {
        Self {
            words,
            marker: PhantomData,
        }
    }

    /// 從 canonical little-endian limbs 建立元素。
    pub fn from_words(words: [u32; N]) -> Option<Self> {
        // Canonical-input validation intentionally exposes acceptance through Option.
        (gte(&words, &S::P).unwrap_u8() == 0).then_some(Self::new_unchecked(words))
    }

    /// 從固定寬整數建立元素。
    pub fn from_integer(value: &S::Integer) -> Option<Self> {
        let mut words = [0_u32; N];
        value.write_unsigned_le_u32(&mut words).ok()?;
        Self::from_words(words)
    }

    /// 轉回曲線選定的固定寬整數。
    pub fn to_integer(self) -> S::Integer {
        S::Integer::from_unsigned_le_u32(&self.words)
            .unwrap_or_else(|_| panic!("{} field value fits its integer type", S::NAME))
    }

    /// 寫入固定寬 big-endian 座標。
    pub fn encode_to(&self, output: &mut [u8]) {
        assert_eq!(output.len(), S::BYTES, "field encoding width mismatch");
        output.fill(0);
        for source in 0..S::BYTES {
            let word = source / 4;
            let shift = (source % 4) * 8;
            output[S::BYTES - 1 - source] = (self.words[word] >> shift) as u8;
        }
    }

    /// 底層 little-endian words。
    pub const fn as_words(&self) -> &[u32; N] {
        &self.words
    }

    /// 是否為零。
    pub fn is_zero(&self) -> bool {
        is_zero(&self.words)
    }

    /// 是否為一。
    pub fn is_one(&self) -> bool {
        is_one(&self.words)
    }

    /// 最低位元。
    pub const fn test_bit_zero(&self) -> bool {
        self.words[0] & 1 != 0
    }

    /// 體域加法。
    pub fn add(&self, rhs: &Self) -> Self {
        Self::new_unchecked(SpecializedField::<S, N>::add(&self.words, &rhs.words))
    }

    /// 體域減法。
    pub fn subtract(&self, rhs: &Self) -> Self {
        Self::new_unchecked(SpecializedField::<S, N>::subtract(&self.words, &rhs.words))
    }

    /// 體域乘法。
    pub fn multiply(&self, rhs: &Self) -> Self {
        Self::new_unchecked(SpecializedField::<S, N>::multiply(&self.words, &rhs.words))
    }

    /// 體域平方。
    pub fn square(&self) -> Self {
        Self::new_unchecked(SpecializedField::<S, N>::square(&self.words))
    }

    /// 加法反元素。
    pub fn negate(&self) -> Self {
        Self::new_unchecked(SpecializedField::<S, N>::negate(&self.words))
    }

    /// 乘法反元素。
    pub fn invert(&self) -> Option<Self> {
        SpecializedField::<S, N>::invert(&self.words).map(Self::new_unchecked)
    }

    /// Tonelli-Shanks 平方根；點解壓縮處理的是公開座標，因此此流程允許變動時間。
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() || self.is_one() {
            return Some(*self);
        }

        let mut q = S::P;
        sub_small(&mut q, 1);
        let mut s = 0_usize;
        while q[0] & 1 == 0 {
            shr_one(&mut q);
            s += 1;
        }

        if s == 1 {
            let mut exponent = S::P;
            add_small(&mut exponent, 1);
            shr_one(&mut exponent);
            shr_one(&mut exponent);
            let root = self.pow(&exponent);
            return (root.square() == *self).then_some(root);
        }

        let mut euler = S::P;
        sub_small(&mut euler, 1);
        shr_one(&mut euler);
        let mut candidate = 2_u32;
        let z = loop {
            let value = Self::from_small(candidate);
            if value.pow(&euler) != Self::ONE {
                break value;
            }
            candidate += 1;
        };

        let mut c = z.pow(&q);
        let mut q_plus_one = q;
        add_small(&mut q_plus_one, 1);
        shr_one(&mut q_plus_one);
        let mut x = self.pow(&q_plus_one);
        let mut t = self.pow(&q);
        let mut m = s;

        while t != Self::ONE {
            let mut i = 1_usize;
            let mut t2i = t.square();
            while i < m && t2i != Self::ONE {
                t2i = t2i.square();
                i += 1;
            }
            if i == m {
                return None;
            }
            let b = c.square_pow(m - i - 1);
            x = x.multiply(&b);
            c = b.square();
            t = t.multiply(&c);
            m = i;
        }

        (x.square() == *self).then_some(x)
    }

    fn from_small(value: u32) -> Self {
        let mut words = [0_u32; N];
        words[0] = value;
        Self::new_unchecked(words)
    }

    fn pow(&self, exponent: &[u32; N]) -> Self {
        let mut result = Self::ONE;
        for word in exponent.iter().rev() {
            for bit in (0..32).rev() {
                result = result.square();
                if word >> bit & 1 != 0 {
                    result = result.multiply(self);
                }
            }
        }
        result
    }

    fn square_pow(&self, count: usize) -> Self {
        Self::new_unchecked(SpecializedField::<S, N>::square_n(&self.words, count))
    }
}

impl<S: PrimeFieldSpec<N>, const N: usize> FieldElement for SpecializedFieldElement<S, N> {
    fn is_zero(&self) -> bool {
        self.is_zero()
    }

    fn is_one(&self) -> bool {
        self.is_one()
    }

    fn add(&self, rhs: &Self) -> Self {
        self.add(rhs)
    }

    fn sub(&self, rhs: &Self) -> Self {
        self.subtract(rhs)
    }

    fn mul(&self, rhs: &Self) -> Self {
        self.multiply(rhs)
    }

    fn square(&self) -> Self {
        self.square()
    }

    fn sqrt(&self) -> Option<Self> {
        self.sqrt()
    }

    fn negate(&self) -> Self {
        self.negate()
    }

    fn invert(&self) -> Option<Self> {
        self.invert()
    }
}

impl<S: PrimeFieldSpec<N>, const N: usize> PrimeFieldElement for SpecializedFieldElement<S, N> {
    type BigUint = S::Integer;

    fn element_from_big_uint(&self, value: &Self::BigUint) -> Self {
        Self::from_integer(value)
            .unwrap_or_else(|| panic!("field element must be smaller than {} modulus", S::NAME))
    }

    fn to_big_uint(&self) -> Self::BigUint {
        self.to_integer()
    }
}

impl<S: PrimeFieldSpec<N>, const N: usize> Add for &SpecializedFieldElement<S, N> {
    type Output = SpecializedFieldElement<S, N>;

    fn add(self, rhs: Self) -> Self::Output {
        SpecializedFieldElement::add(self, rhs)
    }
}

impl<S: PrimeFieldSpec<N>, const N: usize> Sub for &SpecializedFieldElement<S, N> {
    type Output = SpecializedFieldElement<S, N>;

    fn sub(self, rhs: Self) -> Self::Output {
        SpecializedFieldElement::subtract(self, rhs)
    }
}

impl<S: PrimeFieldSpec<N>, const N: usize> Mul for &SpecializedFieldElement<S, N> {
    type Output = SpecializedFieldElement<S, N>;

    fn mul(self, rhs: Self) -> Self::Output {
        SpecializedFieldElement::multiply(self, rhs)
    }
}

impl<S: PrimeFieldSpec<N>, const N: usize> Neg for &SpecializedFieldElement<S, N> {
    type Output = SpecializedFieldElement<S, N>;

    fn neg(self) -> Self::Output {
        self.negate()
    }
}

impl<S: PrimeFieldSpec<N>, const N: usize> Debug for SpecializedFieldElement<S, N> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple(S::NAME)
            .field(&self.to_integer())
            .finish()
    }
}

fn reduce<S: PrimeFieldSpec<N>, const N: usize>(wide: &[u32; MAX_WIDE_LIMBS]) -> [u32; N] {
    match S::REDUCTION {
        ReductionKind::Sm2 => reduce_solinas::<S, N>(wide),
        ReductionKind::P128 => reduce_p128::<S, N>(wide),
        ReductionKind::SmallComplement(complement) => {
            reduce_small_complement::<S, N>(wide, complement)
        }
        ReductionKind::P384 => reduce_p384::<S, N>(wide),
        ReductionKind::P192R1 => reduce_p192r1::<S, N>(wide),
        ReductionKind::P224R1 => reduce_p224r1::<S, N>(wide),
        ReductionKind::Mersenne521 => reduce_mersenne_521::<S, N>(wide),
    }
}

fn reduce_solinas<S: PrimeFieldSpec<N>, const N: usize>(wide: &[u32; MAX_WIDE_LIMBS]) -> [u32; N] {
    let complement = modulus_complement::<S, N>();
    let complement_len = significant_len(&complement);
    let mut current = *wide;

    while bit_length(&current) > S::BITS {
        let mut low = [0_u32; MAX_WIDE_LIMBS];
        let full_words = S::BITS / 32;
        let partial_bits = S::BITS % 32;
        low[..full_words].copy_from_slice(&current[..full_words]);
        if partial_bits != 0 {
            low[full_words] = current[full_words] & ((1_u32 << partial_bits) - 1);
        }

        let mut high = [0_u32; MAX_WIDE_LIMBS];
        shift_right_into(&current, S::BITS, &mut high);
        let high_len = significant_len(&high);
        let mut next = multiply_slices(&high[..high_len], &complement[..complement_len]);
        add_assign(&mut next, &low);
        current = next;
    }

    let mut result = [0_u32; N];
    result.copy_from_slice(&current[..N]);
    if S::BITS % 32 != 0 {
        result[N - 1] &= (1_u32 << (S::BITS % 32)) - 1;
    }
    // This public-value reduction path intentionally reveals the comparison.
    while gte(&result, &S::P).unwrap_u8() != 0 {
        result = sub_words(&result, &S::P).0;
    }
    result
}

fn reduce_p128<S: PrimeFieldSpec<N>, const N: usize>(wide: &[u32; MAX_WIDE_LIMBS]) -> [u32; N] {
    debug_assert_eq!(N, 4);
    let mut x0 = u64::from(wide[0]);
    let mut x1 = u64::from(wide[1]);
    let mut x2 = u64::from(wide[2]);
    let mut x3 = u64::from(wide[3]);
    let mut x4 = u64::from(wide[4]);
    let mut x5 = u64::from(wide[5]);
    let mut x6 = u64::from(wide[6]);
    let x7 = u64::from(wide[7]);

    x3 += x7;
    x6 += x7 << 1;
    x2 += x6;
    x5 += x6 << 1;
    x1 += x5;
    x4 += x5 << 1;
    x0 += x4;
    x3 += x4 << 1;

    let mut result = [0_u32; N];
    result[0] = x0 as u32;
    x1 += x0 >> 32;
    result[1] = x1 as u32;
    x2 += x1 >> 32;
    result[2] = x2 as u32;
    x3 += x2 >> 32;
    result[3] = x3 as u32;
    let mut overflow = (x3 >> 32) as u32;

    while overflow != 0 {
        let value = u64::from(overflow);
        let mut carry = u64::from(result[0]) + value;
        result[0] = carry as u32;
        carry >>= 32;
        for word in result.iter_mut().take(3).skip(1) {
            if carry == 0 {
                break;
            }
            carry += u64::from(*word);
            *word = carry as u32;
            carry >>= 32;
        }
        carry += u64::from(result[3]) + (value << 1);
        result[3] = carry as u32;
        overflow = (carry >> 32) as u32;
    }
    canonicalize::<S, N>(result, false)
}

fn reduce_p192r1<S: PrimeFieldSpec<N>, const N: usize>(wide: &[u32; MAX_WIDE_LIMBS]) -> [u32; N] {
    debug_assert_eq!(N, 6);
    let xx06 = u64::from(wide[6]);
    let xx07 = u64::from(wide[7]);
    let xx08 = u64::from(wide[8]);
    let xx09 = u64::from(wide[9]);
    let xx10 = u64::from(wide[10]);
    let xx11 = u64::from(wide[11]);
    let mut t0 = xx06 + xx10;
    let mut t1 = xx07 + xx11;

    let mut result = [0_u32; N];
    let mut carry = u64::from(wide[0]) + t0;
    let z0 = carry as u32;
    carry >>= 32;
    carry += u64::from(wide[1]) + t1;
    result[1] = carry as u32;
    carry >>= 32;
    t0 += xx08;
    t1 += xx09;
    carry += u64::from(wide[2]) + t0;
    let mut z2 = u64::from(carry as u32);
    carry >>= 32;
    carry += u64::from(wide[3]) + t1;
    result[3] = carry as u32;
    carry >>= 32;
    t0 -= xx06;
    t1 -= xx07;
    carry += u64::from(wide[4]) + t0;
    result[4] = carry as u32;
    carry >>= 32;
    carry += u64::from(wide[5]) + t1;
    result[5] = carry as u32;
    carry >>= 32;

    z2 += carry;
    carry += u64::from(z0);
    result[0] = carry as u32;
    carry >>= 32;
    if carry != 0 {
        carry += u64::from(result[1]);
        result[1] = carry as u32;
        z2 += carry >> 32;
    }
    result[2] = z2 as u32;
    let carry = z2 >> 32;
    debug_assert!(carry <= 1);
    let overflow = carry != 0 && increment_at(&mut result, 3);
    canonicalize::<S, N>(result, overflow)
}

fn reduce_p224r1<S: PrimeFieldSpec<N>, const N: usize>(wide: &[u32; MAX_WIDE_LIMBS]) -> [u32; N] {
    debug_assert_eq!(N, 7);
    let xx10 = i64::from(wide[10]);
    let xx11 = i64::from(wide[11]);
    let xx12 = i64::from(wide[12]);
    let xx13 = i64::from(wide[13]);
    let t0 = i64::from(wide[7]) + xx11 - 1;
    let t1 = i64::from(wide[8]) + xx12;
    let t2 = i64::from(wide[9]) + xx13;

    let mut result = [0_u32; N];
    let mut carry = i64::from(wide[0]) - t0;
    let mut z0 = i64::from(carry as u32);
    carry >>= 32;
    carry += i64::from(wide[1]) - t1;
    result[1] = carry as u32;
    carry >>= 32;
    carry += i64::from(wide[2]) - t2;
    result[2] = carry as u32;
    carry >>= 32;
    carry += i64::from(wide[3]) + t0 - xx10;
    let mut z3 = i64::from(carry as u32);
    carry >>= 32;
    carry += i64::from(wide[4]) + t1 - xx11;
    result[4] = carry as u32;
    carry >>= 32;
    carry += i64::from(wide[5]) + t2 - xx12;
    result[5] = carry as u32;
    carry >>= 32;
    carry += i64::from(wide[6]) + xx10 - xx13;
    result[6] = carry as u32;
    carry >>= 32;
    carry += 1;
    debug_assert!(carry >= 0);

    z3 += carry;
    z0 -= carry;
    result[0] = z0 as u32;
    carry = z0 >> 32;
    if carry != 0 {
        carry += i64::from(result[1]);
        result[1] = carry as u32;
        carry >>= 32;
        carry += i64::from(result[2]);
        result[2] = carry as u32;
        z3 += carry >> 32;
    }
    result[3] = z3 as u32;
    carry = z3 >> 32;
    debug_assert!(carry == 0 || carry == 1);
    let overflow = carry != 0 && increment_at(&mut result, 4);
    canonicalize::<S, N>(result, overflow)
}

fn canonicalize<S: PrimeFieldSpec<N>, const N: usize>(
    mut result: [u32; N],
    overflow: bool,
) -> [u32; N] {
    if overflow {
        let mut wide = [0_u32; MAX_WIDE_LIMBS];
        wide[..N].copy_from_slice(&result);
        wide[N] = 1;
        return reduce_solinas::<S, N>(&wide);
    }
    // This public-value reduction path intentionally reveals the comparison.
    if gte(&result, &S::P).unwrap_u8() != 0 {
        result = sub_words(&result, &S::P).0;
    }
    result
}

fn increment_at<const N: usize>(words: &mut [u32; N], start: usize) -> bool {
    for word in &mut words[start..] {
        let (next, overflow) = word.overflowing_add(1);
        *word = next;
        if !overflow {
            return false;
        }
    }
    true
}

fn reduce_small_complement<S: PrimeFieldSpec<N>, const N: usize>(
    wide: &[u32; MAX_WIDE_LIMBS],
    complement: u64,
) -> [u32; N] {
    debug_assert_eq!(S::BITS, N * 32);
    let mut accumulator = [0_u32; MAX_WIDE_LIMBS];
    accumulator[..N].copy_from_slice(&wide[..N]);

    let mut carry = 0_u128;
    for index in 0..N {
        let sum = u128::from(accumulator[index])
            + u128::from(wide[N + index]) * u128::from(complement)
            + carry;
        accumulator[index] = sum as u32;
        carry = sum >> 32;
    }
    let mut index = N;
    while carry != 0 {
        accumulator[index] = carry as u32;
        carry >>= 32;
        index += 1;
    }

    while accumulator[N..].iter().any(|word| *word != 0) {
        let high = u128::from(accumulator[N]) | (u128::from(accumulator[N + 1]) << 32);
        debug_assert!(accumulator[N + 2..].iter().all(|word| *word == 0));
        accumulator[N..].fill(0);

        let mut folded = high * u128::from(complement);
        let mut carry = 0_u64;
        let mut index = 0_usize;
        while folded != 0 || carry != 0 {
            let sum = u64::from(accumulator[index]) + u64::from(folded as u32) + carry;
            accumulator[index] = sum as u32;
            carry = sum >> 32;
            folded >>= 32;
            index += 1;
        }
    }

    let mut result = [0_u32; N];
    result.copy_from_slice(&accumulator[..N]);
    // This public-value reduction path intentionally reveals the comparison.
    while gte(&result, &S::P).unwrap_u8() != 0 {
        result = sub_words(&result, &S::P).0;
    }
    result
}

fn reduce_p384<S: PrimeFieldSpec<N>, const N: usize>(wide: &[u32; MAX_WIDE_LIMBS]) -> [u32; N] {
    debug_assert_eq!(N, 12);
    let xx16 = i64::from(wide[16]);
    let xx17 = i64::from(wide[17]);
    let xx18 = i64::from(wide[18]);
    let xx19 = i64::from(wide[19]);
    let xx20 = i64::from(wide[20]);
    let xx21 = i64::from(wide[21]);
    let xx22 = i64::from(wide[22]);
    let xx23 = i64::from(wide[23]);

    let t0 = i64::from(wide[12]) + xx20 - 1;
    let t1 = i64::from(wide[13]) + xx22;
    let t2 = i64::from(wide[14]) + xx22 + xx23;
    let t3 = i64::from(wide[15]) + xx23;
    let t4 = xx17 + xx21;
    let t5 = xx21 - xx23;
    let t6 = xx22 - xx23;
    let t7 = t0 + t5;
    let terms = [
        i64::from(wide[0]) + t7,
        i64::from(wide[1]) + xx23 - t0 + t1,
        i64::from(wide[2]) - xx21 - t1 + t2,
        i64::from(wide[3]) - t2 + t3 + t7,
        i64::from(wide[4]) + xx16 + xx21 + t1 - t3 + t7,
        i64::from(wide[5]) - xx16 + t1 + t2 + t4,
        i64::from(wide[6]) + xx18 - xx17 + t2 + t3,
        i64::from(wide[7]) + xx16 + xx19 - xx18 + t3,
        i64::from(wide[8]) + xx16 + xx17 + xx20 - xx19,
        i64::from(wide[9]) + xx18 - xx20 + t4,
        i64::from(wide[10]) + xx18 + xx19 - t5 + t6,
        i64::from(wide[11]) + xx19 + xx20 - t6,
    ];

    let mut folded = [0_u32; MAX_WIDE_LIMBS];
    let mut carry = 0_i64;
    for (index, term) in terms.into_iter().enumerate() {
        carry += term;
        folded[index] = carry as u32;
        carry >>= 32;
    }
    carry += 1;
    debug_assert!(carry >= 0);
    let mut index = 12;
    let mut carry = carry as u64;
    while carry != 0 {
        folded[index] = carry as u32;
        carry >>= 32;
        index += 1;
    }
    reduce_solinas::<S, N>(&folded)
}

fn reduce_mersenne_521<S: PrimeFieldSpec<N>, const N: usize>(
    wide: &[u32; MAX_WIDE_LIMBS],
) -> [u32; N] {
    debug_assert_eq!(S::BITS, 521);
    let mut current = *wide;
    while bit_length(&current) > 521 {
        let mut low = [0_u32; MAX_WIDE_LIMBS];
        low[..16].copy_from_slice(&current[..16]);
        low[16] = current[16] & 0x1ff;
        let mut high = [0_u32; MAX_WIDE_LIMBS];
        shift_right_into(&current, 521, &mut high);
        add_assign(&mut low, &high);
        current = low;
    }
    let mut result = [0_u32; N];
    result.copy_from_slice(&current[..N]);
    // This public-value reduction path intentionally reveals the comparison.
    while gte(&result, &S::P).unwrap_u8() != 0 {
        result = sub_words(&result, &S::P).0;
    }
    result
}

fn modulus_complement<S: PrimeFieldSpec<N>, const N: usize>() -> [u32; MAX_WIDE_LIMBS] {
    let mut result = [0_u32; MAX_WIDE_LIMBS];
    let word = S::BITS / 32;
    let bit = S::BITS % 32;
    result[word] = 1_u32 << bit;
    let mut borrow = 0_u64;
    for (index, word) in result.iter_mut().enumerate() {
        let subtrahend = u64::from(if index < N { S::P[index] } else { 0 }) + borrow;
        let minuend = u64::from(*word);
        *word = minuend.wrapping_sub(subtrahend) as u32;
        borrow = u64::from(minuend < subtrahend);
    }
    debug_assert_eq!(borrow, 0);
    result
}

fn multiply_wide<const N: usize>(left: &[u32; N], right: &[u32; N]) -> [u32; MAX_WIDE_LIMBS] {
    multiply_slices(left, right)
}

fn multiply_slices(left: &[u32], right: &[u32]) -> [u32; MAX_WIDE_LIMBS] {
    let mut result = [0_u32; MAX_WIDE_LIMBS];
    for (left_index, left_word) in left.iter().enumerate() {
        let mut carry = 0_u64;
        for (right_index, right_word) in right.iter().enumerate() {
            let index = left_index + right_index;
            let sum =
                u64::from(result[index]) + u64::from(*left_word) * u64::from(*right_word) + carry;
            result[index] = sum as u32;
            carry = sum >> 32;
        }
        let mut index = left_index + right.len();
        while carry != 0 {
            let sum = u64::from(result[index]) + carry;
            result[index] = sum as u32;
            carry = sum >> 32;
            index += 1;
        }
    }
    result
}

fn add_assign(result: &mut [u32; MAX_WIDE_LIMBS], value: &[u32; MAX_WIDE_LIMBS]) {
    let mut carry = 0_u64;
    for index in 0..MAX_WIDE_LIMBS {
        let sum = u64::from(result[index]) + u64::from(value[index]) + carry;
        result[index] = sum as u32;
        carry = sum >> 32;
    }
    debug_assert_eq!(carry, 0);
}

fn shift_right_into(
    input: &[u32; MAX_WIDE_LIMBS],
    count: usize,
    output: &mut [u32; MAX_WIDE_LIMBS],
) {
    let words = count / 32;
    let bits = count % 32;
    for index in 0..(MAX_WIDE_LIMBS - words) {
        let low = input[index + words] >> bits;
        let high = if bits != 0 && index + words + 1 < MAX_WIDE_LIMBS {
            input[index + words + 1] << (32 - bits)
        } else {
            0
        };
        output[index] = low | high;
    }
}

fn bit_length(words: &[u32; MAX_WIDE_LIMBS]) -> usize {
    words
        .iter()
        .rposition(|word| *word != 0)
        .map_or(0, |index| {
            index * 32 + (32 - words[index].leading_zeros() as usize)
        })
}

fn significant_len(words: &[u32; MAX_WIDE_LIMBS]) -> usize {
    words
        .iter()
        .rposition(|word| *word != 0)
        .map_or(0, |i| i + 1)
}

pub(crate) fn is_zero<const N: usize>(value: &[u32; N]) -> bool {
    value.iter().all(|word| *word == 0)
}

pub(crate) fn is_one<const N: usize>(value: &[u32; N]) -> bool {
    value.first() == Some(&1) && value[1..].iter().all(|word| *word == 0)
}

/// Compares little-endian limbs without exposing the result or exiting early.
pub(crate) fn gte<const N: usize>(left: &[u32; N], right: &[u32; N]) -> Choice {
    let mut greater_or_equal = Choice::from_lsb(1);
    for (left, right) in left.iter().zip(right) {
        // A more significant unequal limb overrides all lower limbs.
        greater_or_equal = left.ct_ge(right) & (!left.ct_eq(right) | greater_or_equal);
    }
    greater_or_equal
}

fn add_words<const N: usize>(left: &[u32; N], right: &[u32; N]) -> ([u32; N], bool) {
    let mut result = [0_u32; N];
    let mut carry = 0_u64;
    for index in 0..N {
        let sum = u64::from(left[index]) + u64::from(right[index]) + carry;
        result[index] = sum as u32;
        carry = sum >> 32;
    }
    (result, carry != 0)
}

fn sub_words<const N: usize>(left: &[u32; N], right: &[u32; N]) -> ([u32; N], bool) {
    let mut result = [0_u32; N];
    let mut borrow = 0_u64;
    for index in 0..N {
        let subtrahend = u64::from(right[index]) + borrow;
        let minuend = u64::from(left[index]);
        result[index] = minuend.wrapping_sub(subtrahend) as u32;
        borrow = u64::from(minuend < subtrahend);
    }
    (result, borrow != 0)
}

fn add_small<const N: usize>(words: &mut [u32; N], value: u32) {
    let mut carry = u64::from(value);
    for word in words {
        let sum = u64::from(*word) + carry;
        *word = sum as u32;
        carry = sum >> 32;
        if carry == 0 {
            break;
        }
    }
}

fn sub_small<const N: usize>(words: &mut [u32; N], value: u32) {
    let mut borrow = u64::from(value);
    for word in words {
        let minuend = u64::from(*word);
        *word = minuend.wrapping_sub(borrow) as u32;
        borrow = u64::from(minuend < borrow);
        if borrow == 0 {
            break;
        }
    }
}

fn shr_one<const N: usize>(words: &mut [u32; N]) {
    let mut carry = 0_u32;
    for word in words.iter_mut().rev() {
        let next = *word << 31;
        *word = (*word >> 1) | carry;
        carry = next;
    }
}
