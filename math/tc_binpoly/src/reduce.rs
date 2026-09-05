use crate::ops::size;

/// Reduction of a double-width carryless product modulo a binary polynomial.
pub trait Reduce {
    /// Reduces `tt` into `z`. The input scratch is disposable and may be mutated.
    fn reduce(&self, tt: &mut [u64], z: &mut [u64]);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Reducer {
    Binomial(BinomialReducer),
    Trinomial(TrinomialReducer),
    Pentanomial(PentanomialReducer),
}

impl Reducer {
    pub(crate) fn binomial(n: usize) -> Self {
        let reducer = if n & 63 == 0 {
            BinomialReducer::Aligned { n }
        } else {
            BinomialReducer::Unaligned { n }
        };
        Self::Binomial(reducer)
    }

    pub(crate) fn trinomial(n: usize, k: usize) -> Self {
        Self::Trinomial(TrinomialReducer::new(n, k))
    }

    pub(crate) fn pentanomial(n: usize, k1: usize, k2: usize, k3: usize) -> Self {
        Self::Pentanomial(PentanomialReducer::new(n, k1, k2, k3))
    }

    pub(crate) const fn is_binomial(&self) -> bool {
        matches!(self, Self::Binomial(_))
    }
}

impl Reduce for Reducer {
    fn reduce(&self, tt: &mut [u64], z: &mut [u64]) {
        match self {
            Self::Binomial(reducer) => reducer.reduce(tt, z),
            Self::Trinomial(reducer) => reducer.reduce(tt, z),
            Self::Pentanomial(reducer) => reducer.reduce(tt, z),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BinomialReducer {
    /// `n % 64 != 0`: the result has a partial top limb.
    Unaligned { n: usize },
    /// `n % 64 == 0`: high limbs fold directly onto low limbs.
    Aligned { n: usize },
}

impl Reduce for BinomialReducer {
    fn reduce(&self, tt: &mut [u64], z: &mut [u64]) {
        let n = match *self {
            Self::Unaligned { n } | Self::Aligned { n } => n,
        };
        let words = size(n);
        assert_eq!(z.len(), words, "invalid reduced output length");
        assert!(tt.len() >= words * 2, "invalid extended input length");
        debug_assert_product_slack(n, tt);

        match *self {
            Self::Aligned { .. } => {
                for i in 0..words {
                    z[i] = tt[i] ^ tt[words + i];
                }
            }
            Self::Unaligned { .. } => {
                // Correctness-first fold for x^n == 1. The optimized BC
                // Unaligned splice will replace this body without changing
                // the enum dispatch surface.
                for p in (n..=2 * n - 2).rev() {
                    let bit = bit_value(tt, p);
                    xor_bit_value(tt, p - n, bit);
                }
                z.copy_from_slice(&tt[..words]);
                mask_top(n, z);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TrinomialParameters {
    n: usize,
    k: usize,
}

impl TrinomialParameters {
    fn reduce_d(self, tt: &mut [u64], z: &mut [u64]) {
        let words = size(self.n);
        assert_eq!(z.len(), words, "invalid reduced output length");
        assert!(tt.len() >= words * 2, "invalid extended input length");
        debug_assert_product_slack(self.n, tt);

        // Generic top-down reducer D. Every bit x^p, p >= n, folds to
        // x^(p-n) + x^(p-n+k). Newly-created high terms have smaller degree
        // and are therefore visited later by this descending loop.
        for p in (self.n..=2 * self.n - 2).rev() {
            let bit = bit_value(tt, p);
            xor_bit_value(tt, p - self.n, bit);
            xor_bit_value(tt, p - self.n + self.k, bit);
        }
        z.copy_from_slice(&tt[..words]);
        mask_top(self.n, z);
    }

    fn reduce_words(self, tt: &mut [u64], z: &mut [u64]) {
        reduce_words(self.n, self.k, &[0, self.k], tt, z);
    }
}

/// Trinomial reducer dispatch.
///
/// The variants mirror BC's 15 reducer classes up front so replacing the
/// generic D body with specialized word-at-a-time kernels does not require a
/// later trait-object-to-enum redesign.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrinomialReducer {
    A(TrinomialParameters),
    A3(TrinomialParameters),
    A4(TrinomialParameters),
    A5(TrinomialParameters),
    A6(TrinomialParameters),
    A7(TrinomialParameters),
    A8(TrinomialParameters),
    B(TrinomialParameters),
    C(TrinomialParameters),
    C5(TrinomialParameters),
    C6(TrinomialParameters),
    C7(TrinomialParameters),
    C8(TrinomialParameters),
    D(TrinomialParameters),
    E(TrinomialParameters),
}

impl TrinomialReducer {
    fn new(n: usize, k: usize) -> Self {
        let p = TrinomialParameters { n, k };

        // ORDER-CRITICAL, matching BC TrinomialReduce.Create:
        // 0. word-aligned n first (all partial-top-limb reducers exclude it);
        // 1. n-k < 64 requires iterative bit folding;
        // 2. k < 64 selects A before the B/C split;
        // 3. word-aligned k selects B before C;
        // 4. the remaining domain selects C.
        if n & 63 == 0 {
            return if n - k >= 64 && k & 63 != 0 {
                Self::E(p)
            } else {
                Self::D(p)
            };
        }
        if n - k < 64 {
            return Self::D(p);
        }
        if k < 64 {
            return match n / 32 {
                2 => Self::A3(p),
                3 => Self::A4(p),
                4 => Self::A5(p),
                5 => Self::A6(p),
                6 => Self::A7(p),
                7 => Self::A8(p),
                _ => Self::A(p),
            };
        }
        if k & 63 == 0 {
            return Self::B(p);
        }
        match n / 32 {
            4 => Self::C5(p),
            5 => Self::C6(p),
            6 => Self::C7(p),
            7 => Self::C8(p),
            _ => Self::C(p),
        }
    }

    fn parameters(&self) -> TrinomialParameters {
        match *self {
            Self::A(p)
            | Self::A3(p)
            | Self::A4(p)
            | Self::A5(p)
            | Self::A6(p)
            | Self::A7(p)
            | Self::A8(p)
            | Self::B(p)
            | Self::C(p)
            | Self::C5(p)
            | Self::C6(p)
            | Self::C7(p)
            | Self::C8(p)
            | Self::D(p)
            | Self::E(p) => p,
        }
    }
}

impl Reduce for TrinomialReducer {
    fn reduce(&self, tt: &mut [u64], z: &mut [u64]) {
        match self {
            // D is the correctness fallback for the overlapping or residual
            // word-aligned domains.
            Self::D(p) => p.reduce_d(tt, z),
            // The remaining variants share a word-at-a-time top-down fold.
            // Their enum identities preserve BC's narrower future unrolling
            // opportunities (including the A3/A5/A7 slack cases).
            _ => self.parameters().reduce_words(tt, z),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PentanomialParameters {
    n: usize,
    k1: usize,
    k2: usize,
    k3: usize,
}

impl PentanomialParameters {
    fn reduce_c(self, tt: &mut [u64], z: &mut [u64]) {
        let words = size(self.n);
        assert_eq!(z.len(), words, "invalid reduced output length");
        assert!(tt.len() >= words * 2, "invalid extended input length");
        debug_assert_product_slack(self.n, tt);

        // Generic top-down reducer C. Note that BC uses D as the trinomial
        // fallback but C as the pentanomial fallback.
        for p in (self.n..=2 * self.n - 2).rev() {
            let bit = bit_value(tt, p);
            let q = p - self.n;
            xor_bit_value(tt, q, bit);
            xor_bit_value(tt, q + self.k1, bit);
            xor_bit_value(tt, q + self.k2, bit);
            xor_bit_value(tt, q + self.k3, bit);
        }
        z.copy_from_slice(&tt[..words]);
        mask_top(self.n, z);
    }

    fn reduce_words(self, tt: &mut [u64], z: &mut [u64]) {
        reduce_words(self.n, self.k3, &[0, self.k1, self.k2, self.k3], tt, z);
    }
}

/// Pentanomial reducer dispatch mirroring BC's 11 reducer classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PentanomialReducer {
    A(PentanomialParameters),
    A3(PentanomialParameters),
    A4(PentanomialParameters),
    A5(PentanomialParameters),
    A6(PentanomialParameters),
    A7(PentanomialParameters),
    A8(PentanomialParameters),
    B(PentanomialParameters),
    C(PentanomialParameters),
    D(PentanomialParameters),
    E(PentanomialParameters),
}

impl PentanomialReducer {
    fn new(n: usize, k1: usize, k2: usize, k3: usize) -> Self {
        let p = PentanomialParameters { n, k1, k2, k3 };

        // ORDER-CRITICAL, matching BC PentanomialReduce.Create:
        // 0. word-aligned n first; 1. a near-top k3 needs C; 2. all taps
        // below 64 select A; 3. k2 < 64 selects D; 4. three unaligned taps
        // select B; 5. remaining aligned-tap cases fall back to C.
        if n & 63 == 0 {
            return if n - k3 >= 64 && k1 & 63 != 0 && k2 & 63 != 0 && k3 & 63 != 0 {
                Self::E(p)
            } else {
                Self::C(p)
            };
        }
        if n - k3 < 64 {
            return Self::C(p);
        }
        if k3 < 64 {
            return match n / 32 {
                2 => Self::A3(p),
                3 => Self::A4(p),
                4 => Self::A5(p),
                5 => Self::A6(p),
                6 => Self::A7(p),
                7 => Self::A8(p),
                _ => Self::A(p),
            };
        }
        if k2 < 64 && k3 & 63 != 0 {
            return Self::D(p);
        }
        if k1 & 63 != 0 && k2 & 63 != 0 && k3 & 63 != 0 {
            return Self::B(p);
        }
        Self::C(p)
    }

    fn parameters(&self) -> PentanomialParameters {
        match *self {
            Self::A(p)
            | Self::A3(p)
            | Self::A4(p)
            | Self::A5(p)
            | Self::A6(p)
            | Self::A7(p)
            | Self::A8(p)
            | Self::B(p)
            | Self::C(p)
            | Self::D(p)
            | Self::E(p) => p,
        }
    }
}

impl Reduce for PentanomialReducer {
    fn reduce(&self, tt: &mut [u64], z: &mut [u64]) {
        match self {
            Self::C(p) => p.reduce_c(tt, z),
            _ => self.parameters().reduce_words(tt, z),
        }
    }
}

/// Word-at-a-time top-down fold shared by specialized reducer variants.
///
/// `n - highest_tap >= 64` guarantees every high contribution lands at least
/// one complete block below the source block, so a single descending sweep is
/// sufficient. Unlike BC's final per-family kernels, these generic bit-splice
/// helpers also handle word-aligned taps without relying on masked shift-count
/// behavior.
fn reduce_words(n: usize, highest_tap: usize, taps: &[usize], tt: &mut [u64], z: &mut [u64]) {
    debug_assert!(n - highest_tap >= 64);
    let words = size(n);
    assert_eq!(z.len(), words, "invalid reduced output length");
    assert!(tt.len() >= words * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);

    let mut q = ((n - 2) >> 6) << 6;
    loop {
        let high = extract_word(tt, n + q);
        for &tap in taps {
            xor_word(tt, q + tap, high);
        }
        if q == 0 {
            break;
        }
        q -= 64;
    }

    z.copy_from_slice(&tt[..words]);
    mask_top(n, z);
}

#[inline]
fn extract_word(words: &[u64], bit: usize) -> u64 {
    let index = bit >> 6;
    let shift = bit & 63;
    let mut value = words.get(index).copied().unwrap_or(0) >> shift;
    if shift != 0 {
        value |= words.get(index + 1).copied().unwrap_or(0) << (64 - shift);
    }
    value
}

#[inline]
fn xor_word(words: &mut [u64], bit: usize, value: u64) {
    let index = bit >> 6;
    let shift = bit & 63;
    words[index] ^= value << shift;
    if shift != 0 {
        words[index + 1] ^= value >> (64 - shift);
    }
}

#[inline]
#[cfg(test)]
fn test_bit(words: &[u64], bit: usize) -> bool {
    bit_value(words, bit) != 0
}

#[inline]
fn bit_value(words: &[u64], bit: usize) -> u64 {
    (words[bit >> 6] >> (bit & 63)) & 1
}

#[inline]
fn xor_bit_value(words: &mut [u64], bit: usize, value: u64) {
    words[bit >> 6] ^= value << (bit & 63);
}

#[inline]
#[cfg(test)]
fn toggle_bit(words: &mut [u64], bit: usize) {
    words[bit >> 6] ^= 1_u64 << (bit & 63);
}

fn mask_top(n: usize, z: &mut [u64]) {
    let partial = n & 63;
    if partial != 0 {
        let last = z.len() - 1;
        z[last] &= (1_u64 << partial) - 1;
    }
}

fn debug_assert_product_slack(_n: usize, _tt: &[u64]) {
    #[cfg(debug_assertions)]
    {
        let first_slack = 2 * _n - 1;
        let word = first_slack >> 6;
        let shift = first_slack & 63;
        let mut slack = _tt[word] >> shift;
        for &value in &_tt[word + 1..size(_n) * 2] {
            slack |= value;
        }
        debug_assert_eq!(slack, 0, "extended product contains bits above degree 2n-2");
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn carryless_mul(n: usize, x: &[u64], y: &[u64]) -> Vec<u64> {
        let words = size(n);
        let mut zz = vec![0_u64; words * 2];
        for i in 0..n {
            if !test_bit(x, i) {
                continue;
            }
            for j in 0..n {
                if test_bit(y, j) {
                    toggle_bit(&mut zz, i + j);
                }
            }
        }
        zz
    }

    #[test]
    fn generic_reducers_match_small_hand_computation() {
        // (x^4 + x + 1)(x^3 + 1) = x^7 + x^4 + x^4 + x^3 + x + 1
        // = x^7 + x^3 + x + 1 before reduction.
        let x = [0b1_0011];
        let y = [0b1001];

        let mut tri_tt = carryless_mul(8, &x, &y);
        let mut tri = [0_u64; 1];
        Reducer::trinomial(8, 3).reduce(&mut tri_tt, &mut tri);
        assert_eq!(tri[0], 0b1000_1011);

        let mut penta_tt = carryless_mul(8, &x, &y);
        let mut penta = [0_u64; 1];
        Reducer::pentanomial(8, 1, 3, 4).reduce(&mut penta_tt, &mut penta);
        assert_eq!(penta[0], 0b1000_1011);
    }

    #[test]
    fn aligned_binomial_folds_limb_for_limb() {
        let mut tt = [5_u64, 7];
        let mut z = [0_u64; 1];
        Reducer::binomial(64).reduce(&mut tt, &mut z);
        assert_eq!(z, [2]);
    }

    fn next(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    fn random_reduced(n: usize, seed: &mut u64) -> Vec<u64> {
        let mut value: Vec<_> = (0..size(n)).map(|_| next(seed)).collect();
        if n & 63 != 0 {
            let last = value.len() - 1;
            value[last] &= (1_u64 << (n & 63)) - 1;
        }
        value
    }

    fn assert_trinomial_matches_d(n: usize, k: usize, seed: &mut u64) {
        let x = random_reduced(n, seed);
        let y = random_reduced(n, seed);
        let tt = carryless_mul(n, &x, &y);
        let mut actual_tt = tt.clone();
        let mut expected_tt = tt;
        let mut actual = vec![0_u64; size(n)];
        let mut expected = vec![0_u64; size(n)];
        TrinomialReducer::new(n, k).reduce(&mut actual_tt, &mut actual);
        TrinomialParameters { n, k }.reduce_d(&mut expected_tt, &mut expected);
        assert_eq!(actual, expected, "trinomial n={n}, k={k}");
    }

    fn assert_pentanomial_matches_c(n: usize, k1: usize, k2: usize, k3: usize, seed: &mut u64) {
        let x = random_reduced(n, seed);
        let y = random_reduced(n, seed);
        let tt = carryless_mul(n, &x, &y);
        let mut actual_tt = tt.clone();
        let mut expected_tt = tt;
        let mut actual = vec![0_u64; size(n)];
        let mut expected = vec![0_u64; size(n)];
        PentanomialReducer::new(n, k1, k2, k3).reduce(&mut actual_tt, &mut actual);
        PentanomialParameters { n, k1, k2, k3 }.reduce_c(&mut expected_tt, &mut expected);
        assert_eq!(
            actual, expected,
            "pentanomial n={n}, taps=({k1}, {k2}, {k3})"
        );
    }

    #[test]
    fn trinomial_dispatch_and_every_specialization_match_d() {
        assert!(matches!(
            TrinomialReducer::new(257, 1),
            TrinomialReducer::A(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(65, 1),
            TrinomialReducer::A3(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(97, 1),
            TrinomialReducer::A4(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(129, 1),
            TrinomialReducer::A5(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(161, 1),
            TrinomialReducer::A6(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(193, 1),
            TrinomialReducer::A7(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(225, 1),
            TrinomialReducer::A8(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(257, 64),
            TrinomialReducer::B(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(257, 65),
            TrinomialReducer::C(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(129, 65),
            TrinomialReducer::C5(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(161, 65),
            TrinomialReducer::C6(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(193, 65),
            TrinomialReducer::C7(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(225, 65),
            TrinomialReducer::C8(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(127, 64),
            TrinomialReducer::D(_)
        ));
        assert!(matches!(
            TrinomialReducer::new(192, 65),
            TrinomialReducer::E(_)
        ));

        let mut seed = 0x7A11_CAFE_1234_5678;
        for (n, k) in [
            (257, 1),
            (65, 1),
            (97, 1),
            (129, 1),
            (161, 1),
            (193, 1),
            (225, 1),
            (257, 64),
            (257, 65),
            (129, 65),
            (161, 65),
            (193, 65),
            (225, 65),
            (192, 65),
        ] {
            assert_trinomial_matches_d(n, k, &mut seed);
        }
    }

    #[test]
    fn pentanomial_dispatch_and_every_specialization_match_c() {
        assert!(matches!(
            PentanomialReducer::new(257, 1, 2, 3),
            PentanomialReducer::A(_)
        ));
        assert!(matches!(
            PentanomialReducer::new(67, 1, 2, 3),
            PentanomialReducer::A3(_)
        ));
        assert!(matches!(
            PentanomialReducer::new(97, 1, 2, 3),
            PentanomialReducer::A4(_)
        ));
        assert!(matches!(
            PentanomialReducer::new(129, 1, 2, 3),
            PentanomialReducer::A5(_)
        ));
        assert!(matches!(
            PentanomialReducer::new(161, 1, 2, 3),
            PentanomialReducer::A6(_)
        ));
        assert!(matches!(
            PentanomialReducer::new(193, 1, 2, 3),
            PentanomialReducer::A7(_)
        ));
        assert!(matches!(
            PentanomialReducer::new(225, 1, 2, 3),
            PentanomialReducer::A8(_)
        ));
        assert!(matches!(
            PentanomialReducer::new(257, 1, 65, 67),
            PentanomialReducer::B(_)
        ));
        assert!(matches!(
            PentanomialReducer::new(257, 64, 65, 67),
            PentanomialReducer::C(_)
        ));
        assert!(matches!(
            PentanomialReducer::new(193, 1, 2, 65),
            PentanomialReducer::D(_)
        ));
        assert!(matches!(
            PentanomialReducer::new(192, 1, 2, 65),
            PentanomialReducer::E(_)
        ));

        let mut seed = 0x5EED_5EED_1234_5678;
        for (n, k1, k2, k3) in [
            (257, 1, 2, 3),
            (67, 1, 2, 3),
            (97, 1, 2, 3),
            (129, 1, 2, 3),
            (161, 1, 2, 3),
            (193, 1, 2, 3),
            (225, 1, 2, 3),
            (257, 1, 65, 67),
            (193, 1, 2, 65),
            (192, 1, 2, 65),
        ] {
            assert_pentanomial_matches_c(n, k1, k2, k3, &mut seed);
        }
    }
}
