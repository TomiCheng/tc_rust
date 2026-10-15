use tc_zeroize::Zeroize;

use super::bits::{bit_value, debug_assert_product_slack, mask_top, size, xor_bit_value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TrinomialParameters {
    n: u32,
    k: u32,
}

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
    /// Picks the reduction for `x^n + x^k + 1`, `0 < k < n`, in the order of BC's
    /// `TrinomialReduce.Create`: each test relies on the ones before it.
    pub(crate) fn new(n: u32, k: u32) -> Self {
        let p = TrinomialParameters { n, k };
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

    /// Reduces the product `tt`, of `2 * size(n)` words, into `z`, of `size(n)` words.
    /// `tt` is scratch and is left changed.
    pub(crate) fn reduce(&self, tt: &mut [u64], z: &mut [u64]) {
        match *self {
            Self::A(p) => reduce_a(p.n as usize, p.k as usize, tt, z),
            Self::A3(p) => reduce_a_const::<2, true>(p.n as usize, p.k as usize, tt, z),
            Self::A4(p) => reduce_a_const::<2, false>(p.n as usize, p.k as usize, tt, z),
            Self::A5(p) => reduce_a_const::<3, true>(p.n as usize, p.k as usize, tt, z),
            Self::A6(p) => reduce_a_const::<3, false>(p.n as usize, p.k as usize, tt, z),
            Self::A7(p) => reduce_a_const::<4, true>(p.n as usize, p.k as usize, tt, z),
            Self::A8(p) => reduce_a_const::<4, false>(p.n as usize, p.k as usize, tt, z),
            Self::B(p) => reduce_b(p.n as usize, p.k as usize, tt, z),
            Self::C(p) => reduce_c(p.n as usize, p.k as usize, tt, z),
            Self::C5(p) => reduce_c_const::<3, true>(p.n as usize, p.k as usize, tt, z),
            Self::C6(p) => reduce_c_const::<3, false>(p.n as usize, p.k as usize, tt, z),
            Self::C7(p) => reduce_c_const::<4, true>(p.n as usize, p.k as usize, tt, z),
            Self::C8(p) => reduce_c_const::<4, false>(p.n as usize, p.k as usize, tt, z),
            Self::D(p) => reduce_d(p.n as usize, p.k as usize, tt, z),
            Self::E(p) => reduce_e(p.n as usize, p.k as usize, tt, z),
        }
    }
}

// Every bit x^p, p >= n, folds to x^(p-n) + x^(p-n+k), from the top down.
fn reduce_d(n: usize, k: usize, tt: &mut [u64], z: &mut [u64]) {
    let words = size(n);
    assert_eq!(z.len(), words, "invalid reduced output length");
    assert!(tt.len() >= words * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);
    for p in (n..=2 * n - 2).rev() {
        let bit = bit_value(tt, p);
        xor_bit_value(tt, p - n, bit);
        xor_bit_value(tt, p - n + k, bit);
    }
    z.copy_from_slice(&tt[..words]);
    mask_top(n, z);
}

fn reduce_a(n: usize, k: usize, tt: &mut [u64], z: &mut [u64]) {
    let words = size(n);
    debug_assert!(n & 63 != 0 && k < 64 && n - k >= 64 && words >= 5);
    assert_eq!(z.len(), words, "invalid reduced output length");
    assert!(tt.len() >= words * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);
    let w_n = words - 1;
    let s_n = n & 63;
    let mut pos = w_n;
    let mut t_high = tt[pos + w_n + 1];
    let mut t_low = tt[pos + w_n];
    let first = (t_low >> s_n) | (t_high << (64 - s_n));
    let mut carry = tt[pos] ^ first ^ (first << k);
    tt[pos + 1] ^= first >> (64 - k);

    while pos != 0 {
        pos -= 1;
        t_high = t_low;
        t_low = tt[pos + w_n];
        let t = (t_low >> s_n) | (t_high << (64 - s_n));
        carry ^= t >> (64 - k);
        tt[pos + 1] = carry;
        carry = tt[pos] ^ t ^ (t << k);
    }

    z[0] = carry;
    z[1..w_n].copy_from_slice(&tt[1..w_n]);
    z[w_n] = tt[w_n] & ((1_u64 << s_n) - 1);
}

fn reduce_a_const<const N: usize, const SLACK: bool>(
    n: usize,
    k: usize,
    tt: &[u64],
    z: &mut [u64],
) {
    debug_assert_eq!(size(n), N);
    debug_assert!(n & 63 != 0 && k < 64 && n - k >= 64);
    assert_eq!(z.len(), N, "invalid reduced output length");
    assert!(tt.len() >= N * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);
    let mut local = [[0_u64; N]; 2];
    let words = local.as_flattened_mut();
    let copy_len = if SLACK { N * 2 - 1 } else { N * 2 };
    words[..copy_len].copy_from_slice(&tt[..copy_len]);
    let s_n = n & 63;
    for pos in (0..N).rev() {
        let t = (words[pos + N - 1] >> s_n) | (words[pos + N] << (64 - s_n));
        words[pos] ^= t ^ (t << k);
        words[pos + 1] ^= t >> (64 - k);
    }
    z.copy_from_slice(&words[..N]);
    z[N - 1] &= (1_u64 << s_n) - 1;
    local.zeroize();
}

fn reduce_b(n: usize, k: usize, tt: &mut [u64], z: &mut [u64]) {
    let words = size(n);
    debug_assert!(n & 63 != 0 && k >= 64 && k & 63 == 0 && n - k >= 64);
    assert_eq!(z.len(), words, "invalid reduced output length");
    assert!(tt.len() >= words * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);
    let w_n = words - 1;
    let s_n = n & 63;
    let w_k = k >> 6;
    for pos in (0..=w_n).rev() {
        let t = (tt[pos + w_n] >> s_n) | (tt[pos + w_n + 1] << (64 - s_n));
        tt[pos] ^= t;
        tt[pos + w_k] ^= t;
    }
    z[..w_n].copy_from_slice(&tt[..w_n]);
    z[w_n] = tt[w_n] & ((1_u64 << s_n) - 1);
}

fn reduce_c(n: usize, k: usize, tt: &mut [u64], z: &mut [u64]) {
    let words = size(n);
    debug_assert!(n & 63 != 0 && k >= 64 && k & 63 != 0 && n - k >= 64);
    assert_eq!(z.len(), words, "invalid reduced output length");
    assert!(tt.len() >= words * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);
    let w_n = words - 1;
    let s_n = n & 63;
    let w_k = k >> 6;
    let s_k = k & 63;
    for pos in (0..=w_n).rev() {
        let t = (tt[pos + w_n] >> s_n) | (tt[pos + w_n + 1] << (64 - s_n));
        tt[pos] ^= t;
        tt[pos + w_k] ^= t << s_k;
        tt[pos + w_k + 1] ^= t >> (64 - s_k);
    }
    z[..w_n].copy_from_slice(&tt[..w_n]);
    z[w_n] = tt[w_n] & ((1_u64 << s_n) - 1);
}

fn reduce_c_const<const N: usize, const SLACK: bool>(
    n: usize,
    k: usize,
    tt: &[u64],
    z: &mut [u64],
) {
    debug_assert_eq!(size(n), N);
    debug_assert!(n & 63 != 0 && k >= 64 && k & 63 != 0 && n - k >= 64);
    assert_eq!(z.len(), N, "invalid reduced output length");
    assert!(tt.len() >= N * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);
    let mut local = [[0_u64; N]; 2];
    let words = local.as_flattened_mut();
    let copy_len = if SLACK { N * 2 - 1 } else { N * 2 };
    words[..copy_len].copy_from_slice(&tt[..copy_len]);
    let s_n = n & 63;
    let w_k = k >> 6;
    let s_k = k & 63;
    for pos in (0..N).rev() {
        let t = (words[pos + N - 1] >> s_n) | (words[pos + N] << (64 - s_n));
        words[pos] ^= t;
        words[pos + w_k] ^= t << s_k;
        words[pos + w_k + 1] ^= t >> (64 - s_k);
    }
    z.copy_from_slice(&words[..N]);
    z[N - 1] &= (1_u64 << s_n) - 1;
    local.zeroize();
}

fn reduce_e(n: usize, k: usize, tt: &mut [u64], z: &mut [u64]) {
    let words = size(n);
    debug_assert!(n & 63 == 0 && k & 63 != 0 && n - k >= 64);
    assert_eq!(z.len(), words, "invalid reduced output length");
    assert!(tt.len() >= words * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);
    let w_k = k >> 6;
    let s_k = k & 63;
    for pos in (0..words).rev() {
        let t = tt[pos + words];
        tt[pos] ^= t;
        tt[pos + w_k] ^= t << s_k;
        tt[pos + w_k + 1] ^= t >> (64 - s_k);
    }
    z.copy_from_slice(&tt[..words]);
}

#[cfg(test)]
mod tests {
    use super::super::bits::product;
    use super::TrinomialReducer;

    #[test]
    fn each_shape_of_trinomial_gets_the_reducer_bc_picks() {
        let cases: [(u32, u32, fn(TrinomialReducer) -> bool); 17] = [
            (257, 1, |r| matches!(r, TrinomialReducer::A(_))),
            (65, 1, |r| matches!(r, TrinomialReducer::A3(_))),
            (97, 1, |r| matches!(r, TrinomialReducer::A4(_))),
            (129, 1, |r| matches!(r, TrinomialReducer::A5(_))),
            (161, 1, |r| matches!(r, TrinomialReducer::A6(_))),
            (193, 1, |r| matches!(r, TrinomialReducer::A7(_))),
            (225, 1, |r| matches!(r, TrinomialReducer::A8(_))),
            (257, 64, |r| matches!(r, TrinomialReducer::B(_))),
            (257, 65, |r| matches!(r, TrinomialReducer::C(_))),
            (129, 65, |r| matches!(r, TrinomialReducer::C5(_))),
            (161, 65, |r| matches!(r, TrinomialReducer::C6(_))),
            (193, 65, |r| matches!(r, TrinomialReducer::C7(_))),
            (225, 65, |r| matches!(r, TrinomialReducer::C8(_))),
            (127, 64, |r| matches!(r, TrinomialReducer::D(_))),
            (192, 1, |r| matches!(r, TrinomialReducer::E(_))),
            (192, 65, |r| matches!(r, TrinomialReducer::E(_))),
            (192, 128, |r| matches!(r, TrinomialReducer::D(_))),
        ];
        for (n, k, expected) in cases {
            assert!(expected(TrinomialReducer::new(n, k)), "n = {n}, k = {k}");
        }
    }

    #[test]
    fn every_specialized_reducer_agrees_with_the_bitwise_fold() {
        let shapes = [
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
            (127, 64),
            (192, 1),
            (192, 65),
            (192, 128),
            (113, 9),
            (131, 8),
            (163, 7),
            (233, 74),
            (239, 36),
            (409, 87),
        ];
        for (n, k) in shapes {
            let words = super::size(n);
            for seed in 1..=20 {
                let mut tt = product(n, seed);
                let mut expected_tt = tt.clone();
                let mut z = alloc::vec![0; words];
                let mut expected = alloc::vec![0; words];
                TrinomialReducer::new(n as u32, k as u32).reduce(&mut tt, &mut z);
                super::reduce_d(n, k, &mut expected_tt, &mut expected);
                assert_eq!(z, expected, "n = {n}, k = {k}, seed = {seed}");
            }
        }
    }
}
