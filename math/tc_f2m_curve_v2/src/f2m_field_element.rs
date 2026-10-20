use tc_binpoly::PaddedBinPoly;
use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
use tc_ec_core_v2::{BinaryFieldElement, FieldElement};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct F2mFieldElement {
    value: PaddedBinPoly,
}

impl F2mFieldElement {
    pub(crate) fn new(value: PaddedBinPoly) -> Self {
        Self { value }
    }

    /// BC's `SquarePow`: `x^(2^count)`. Constant time; the work grows with `count`.
    pub fn square_n(&self, count: usize) -> Self {
        Self::new(self.value.square_n(count))
    }

    fn m(&self) -> usize {
        self.value.field().n() as usize
    }

    /// The degree plus one, `0` for zero. Variable time; only for public values.
    pub(crate) fn bit_length(&self) -> usize {
        let limbs = self.value.limbs();
        limbs
            .iter()
            .rposition(|&limb| limb != 0)
            .map_or(0, |i| 64 * i + 64 - limbs[i].leading_zeros() as usize)
    }

    /// BC's `TestBitZero`: the constant coefficient. Constant time.
    pub(crate) fn low_bit(&self) -> u8 {
        (self.value.limbs()[0] & 1) as u8
    }

    /// `x⁻¹`, and `0` for `0`, without revealing which. As constant time as the multiplier.
    pub(crate) fn invert_or_zero(&self) -> Self {
        Self::new(self.value.invert())
    }

    // OR of every limb, with the low bit of the first flipped when `one` is set.
    fn fold(&self, one: bool) -> u64 {
        let limbs = self.value.limbs();
        let first = limbs[0] ^ u64::from(one);
        limbs[1..].iter().fold(first, |acc, &limb| acc | limb)
    }
}

/// Constant time in the value and the choice. Panics when the fields differ.
impl ConditionallySelectable for F2mFieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::new(PaddedBinPoly::conditional_select(
            &a.value, &b.value, choice,
        ))
    }

    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        self.value.conditional_assign(&other.value, choice);
    }

    fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        PaddedBinPoly::conditional_swap(&mut a.value, &mut b.value, choice);
    }
}

/// Constant time; the fields are public.
impl ConstantTimeEq for F2mFieldElement {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.value.ct_eq(&rhs.value)
    }
}

/// Constant time on the x86 backend; tc_binpoly's scalar multiplier, used without
/// PCLMULQDQ, indexes a table by operand bits.
impl FieldElement for F2mFieldElement {
    /// Whether this is zero. Constant time; only the answer is revealed.
    fn is_zero(&self) -> bool {
        self.fold(false) == 0
    }

    /// Whether this is one. Constant time; only the answer is revealed.
    fn is_one(&self) -> bool {
        self.fold(true) == 0
    }

    /// `x + y`, a coefficient-wise XOR. Constant time. Panics when the fields differ.
    fn add(&self, rhs: &Self) -> Self {
        Self::new(self.value.add(&rhs.value))
    }

    /// `x - y`, the same as `x + y` in characteristic 2. Constant time. Panics when the
    /// fields differ.
    fn subtract(&self, rhs: &Self) -> Self {
        self.add(rhs)
    }

    /// `x · y`. Panics when the fields differ.
    fn multiply(&self, rhs: &Self) -> Self {
        Self::new(self.value.multiply(&rhs.value))
    }

    /// `x²`. Constant time.
    fn square(&self) -> Self {
        Self::new(self.value.square())
    }

    /// The square root, `x^(2^(m - 1))`; every element has exactly one. Constant time.
    fn sqrt(&self) -> Option<Self> {
        Some(self.square_n(self.m() - 1))
    }

    /// `-x`, which is `x` in characteristic 2.
    fn negate(&self) -> Self {
        self.clone()
    }

    /// `x⁻¹` by Itoh–Tsujii, or `None` for zero. Only whether there is an inverse is
    /// revealed.
    fn invert(&self) -> Option<Self> {
        (!self.is_zero()).then(|| Self::new(self.value.invert()))
    }

    /// `⌈m / 8⌉`.
    fn encoded_length(&self) -> usize {
        self.m().div_ceil(8)
    }

    /// The coefficients as a big-endian bit string, the top one first. Constant time.
    fn encode_to(&self, output: &mut [u8]) {
        assert_eq!(
            output.len(),
            self.encoded_length(),
            "the output is not the encoded length"
        );
        self.value
            .write_be(output)
            .expect("the output has the length");
    }
}

/// Valid only for an irreducible modulus; the chains depend on `m` alone.
impl BinaryFieldElement for F2mFieldElement {
    /// BC's `Trace`: `x + x^2 + ... + x^(2^(m - 1))` by an addition chain on `m`, which is
    /// `0` or `1`.
    fn trace(&self) -> u8 {
        let m = self.m();
        let mut k = m.ilog2();
        let mut mk = 1;
        let mut tr = self.clone();
        while k > 0 {
            tr = tr.square_n(mk).add(&tr);
            k -= 1;
            mk = m >> k;
            if mk & 1 == 1 {
                tr = tr.square().add(self);
            }
        }
        debug_assert!(tr.is_zero() || tr.is_one());
        u8::from(tr.is_one())
    }

    /// BC's `HalfTrace`: `x + x^4 + ... + x^(4^((m - 1) / 2))`, an `h` with
    /// `h^2 + h = x + trace(x)`. Panics for an even `m`, where it is not defined.
    fn half_trace(&self) -> Self {
        let m = self.m();
        assert!(m & 1 == 1, "half-trace needs an odd degree");
        let n = m.div_ceil(2);
        let mut k = n.ilog2();
        let mut nk = 1;
        let mut ht = self.clone();
        while k > 0 {
            ht = ht.square_n(nk << 1).add(&ht);
            k -= 1;
            nk = n >> k;
            if nk & 1 == 1 {
                ht = ht.square_n(2).add(self);
            }
        }
        ht
    }
}

#[cfg(test)]
mod tests {
    use super::F2mFieldElement;
    use crate::F2mField;
    use tc_constant_time::{Choice, ConditionallySelectable};
    use tc_ec_core_v2::{BinaryFieldElement, FieldElement};

    fn sect163() -> F2mField {
        F2mField::pentanomial(163, 3, 6, 7).unwrap()
    }

    fn values(field: &F2mField) -> alloc::vec::Vec<F2mFieldElement> {
        let mut state = 0x0F2E_1D3C_4B5A_6978_u64;
        let len = (field.m() as usize).div_ceil(8);
        (0..6)
            .map(|_| {
                let mut bytes = alloc::vec![0_u8; len];
                for byte in &mut bytes {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *byte = state as u8;
                }
                bytes[0] &= (1 << (field.m() % 8)) - 1;
                field.element(&bytes).unwrap()
            })
            .collect()
    }

    #[test]
    fn zero_and_one_are_recognized() {
        let field = sect163();
        let (zero, one) = (field.zero(), field.one());
        assert!(zero.is_zero() && !zero.is_one());
        assert!(one.is_one() && !one.is_zero());
        let x = &values(&field)[0];
        assert!(!x.is_zero() && !x.is_one());
    }

    #[test]
    fn addition_is_its_own_inverse() {
        let field = sect163();
        let v = values(&field);
        assert!(v[0].add(&v[0]).is_zero());
        assert_eq!(v[0].subtract(&v[1]), v[0].add(&v[1]));
        assert_eq!(v[0].negate(), v[0]);
    }

    #[test]
    fn a_value_times_its_inverse_is_one_and_zero_has_none() {
        let field = sect163();
        for x in values(&field) {
            assert!(x.multiply(&x.invert().unwrap()).is_one());
        }
        assert_eq!(field.zero().invert(), None);
    }

    #[test]
    fn the_square_root_squares_back() {
        let field = sect163();
        for x in values(&field) {
            assert_eq!(x.sqrt().unwrap().square(), x);
        }
    }

    #[test]
    fn the_trace_is_linear_and_squaring_keeps_it() {
        let field = sect163();
        assert_eq!(field.one().trace(), 1);
        let v = values(&field);
        for pair in v.windows(2) {
            let (x, y) = (&pair[0], &pair[1]);
            assert_eq!(x.square().trace(), x.trace());
            assert_eq!(x.add(y).trace(), x.trace() ^ y.trace());
        }
    }

    #[test]
    fn select_assign_and_swap_follow_the_choice() {
        let field = sect163();
        let v = values(&field);
        let (x, y) = (&v[0], &v[1]);
        let (no, yes) = (Choice::from_lsb(0), Choice::from_lsb(1));
        assert_eq!(&F2mFieldElement::conditional_select(x, y, no), x);
        assert_eq!(&F2mFieldElement::conditional_select(x, y, yes), y);

        let mut z = x.clone();
        z.conditional_assign(y, yes);
        assert_eq!(&z, y);

        let (mut a, mut b) = (x.clone(), y.clone());
        F2mFieldElement::conditional_swap(&mut a, &mut b, yes);
        assert_eq!((&a, &b), (y, x));
        F2mFieldElement::conditional_swap(&mut a, &mut b, no);
        assert_eq!((&a, &b), (y, x));
    }

    #[test]
    fn the_half_trace_solves_h_squared_plus_h_equals_x_plus_its_trace() {
        for field in [sect163(), F2mField::trinomial(233, 74).unwrap()] {
            for x in values(&field) {
                let h = x.half_trace();
                let trace = [field.zero(), field.one()][usize::from(x.trace())].clone();
                assert_eq!(h.square().add(&h), x.add(&trace));
            }
        }
    }
}
