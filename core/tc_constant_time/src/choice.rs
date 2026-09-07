//! One-bit choices and their boolean combinators.

/// A one-bit value for masked selection and composable predicates.
///
/// Construct a choice with [`Self::from_lsb`], which keeps only the input's
/// least significant bit. Combine choices with `!`, `&`, `|`, and `^` without first
/// revealing them. There is no implicit conversion to `bool`; use
/// [`Self::unwrap_u8`] when the bit may be exposed.
///
/// ```
/// use tc_constant_time::Choice;
///
/// let yes = Choice::from_lsb(1);
/// let no = Choice::from_lsb(0);
/// assert_eq!((!yes).unwrap_u8(), 0);
/// assert_eq!((yes & no).unwrap_u8(), 0);
/// assert_eq!((yes | no).unwrap_u8(), 1);
/// assert_eq!((yes ^ yes).unwrap_u8(), 0);
/// ```
#[derive(Clone, Copy)]
pub struct Choice(pub(super) u8);
impl Choice {
    /// Keeps the least significant bit and passes it through an optimization barrier.
    ///
    /// Every `u8` is accepted: even inputs produce zero, and odd inputs produce
    /// one. This is not a test for whether the input is nonzero.
    ///
    /// ```
    /// use tc_constant_time::Choice;
    ///
    /// assert_eq!(Choice::from_lsb(0).unwrap_u8(), 0);
    /// assert_eq!(Choice::from_lsb(2).unwrap_u8(), 0);
    /// assert_eq!(Choice::from_lsb(3).unwrap_u8(), 1);
    /// assert_eq!(Choice::from_lsb(255).unwrap_u8(), 1);
    /// ```
    #[inline(always)]
    pub fn from_lsb(value: u8) -> Self {
        Self(core::hint::black_box(value & 1))
    }
    /// Reveals the bit as zero or one.
    ///
    /// Branching on this result can expose the choice through control flow.
    /// Keep it as a [`Choice`] until that disclosure is intentional.
    ///
    /// ```
    /// use tc_constant_time::ConstantTimeEq;
    ///
    /// let equal = 42_u64.ct_eq(&42);
    /// let revealed: u8 = equal.unwrap_u8();
    /// assert_eq!(revealed, 1);
    /// ```
    #[inline(always)]
    pub fn unwrap_u8(self) -> u8 {
        self.0
    }
}
impl core::ops::Not for Choice {
    type Output = Self;
    fn not(self) -> Self {
        Self(self.0 ^ 1)
    }
}
impl core::ops::BitAnd for Choice {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}
impl core::ops::BitOr for Choice {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl core::ops::BitXor for Choice {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}
