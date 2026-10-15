use super::bits::{bit_value, debug_assert_product_slack, mask_top, size, xor_bit_value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PentanomialParameters {
    n: u32,
    k1: u32,
    k2: u32,
    k3: u32,
}

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
    /// Picks the reduction for `x^n + x^k3 + x^k2 + x^k1 + 1`, `0 < k1 < k2 < k3 < n`, in
    /// the order of BC's `PentanomialReduce.Create`: each test relies on the ones before it.
    pub(crate) fn new(n: u32, k1: u32, k2: u32, k3: u32) -> Self {
        let p = PentanomialParameters { n, k1, k2, k3 };
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

    /// Reduces the product `tt`, of `2 * size(n)` words, into `z`, of `size(n)` words.
    /// `tt` is scratch and is left changed.
    pub(crate) fn reduce(&self, tt: &mut [u64], z: &mut [u64]) {
        match *self {
            Self::A(p) => reduce_a(
                p.n as usize,
                p.k1 as usize,
                p.k2 as usize,
                p.k3 as usize,
                tt,
                z,
            ),
            Self::A3(p) => reduce_a_const::<2, true>(
                p.n as usize,
                p.k1 as usize,
                p.k2 as usize,
                p.k3 as usize,
                tt,
                z,
            ),
            Self::A4(p) => reduce_a_const::<2, false>(
                p.n as usize,
                p.k1 as usize,
                p.k2 as usize,
                p.k3 as usize,
                tt,
                z,
            ),
            Self::A5(p) => reduce_a_const::<3, true>(
                p.n as usize,
                p.k1 as usize,
                p.k2 as usize,
                p.k3 as usize,
                tt,
                z,
            ),
            Self::A6(p) => reduce_a_const::<3, false>(
                p.n as usize,
                p.k1 as usize,
                p.k2 as usize,
                p.k3 as usize,
                tt,
                z,
            ),
            Self::A7(p) => reduce_a_const::<4, true>(
                p.n as usize,
                p.k1 as usize,
                p.k2 as usize,
                p.k3 as usize,
                tt,
                z,
            ),
            Self::A8(p) => reduce_a_const::<4, false>(
                p.n as usize,
                p.k1 as usize,
                p.k2 as usize,
                p.k3 as usize,
                tt,
                z,
            ),
            Self::B(p) => reduce_b(
                p.n as usize,
                p.k1 as usize,
                p.k2 as usize,
                p.k3 as usize,
                tt,
                z,
            ),
            Self::C(p) => reduce_c(
                p.n as usize,
                p.k1 as usize,
                p.k2 as usize,
                p.k3 as usize,
                tt,
                z,
            ),
            Self::D(p) => reduce_d(
                p.n as usize,
                p.k1 as usize,
                p.k2 as usize,
                p.k3 as usize,
                tt,
                z,
            ),
            Self::E(p) => reduce_e(
                p.n as usize,
                p.k1 as usize,
                p.k2 as usize,
                p.k3 as usize,
                tt,
                z,
            ),
        }
    }
}

// Every bit x^p, p >= n, folds to x^(p-n) + x^(p-n+k1) + x^(p-n+k2) + x^(p-n+k3), from
// the top down. BC falls back to C for pentanomials, where trinomials fall back to D.
fn reduce_c(n: usize, k1: usize, k2: usize, k3: usize, tt: &mut [u64], z: &mut [u64]) {
    let words = size(n);
    assert_eq!(z.len(), words, "invalid reduced output length");
    assert!(tt.len() >= words * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);
    for p in (n..=2 * n - 2).rev() {
        let bit = bit_value(tt, p);
        let q = p - n;
        xor_bit_value(tt, q, bit);
        xor_bit_value(tt, q + k1, bit);
        xor_bit_value(tt, q + k2, bit);
        xor_bit_value(tt, q + k3, bit);
    }
    z.copy_from_slice(&tt[..words]);
    mask_top(n, z);
}

fn reduce_a(n: usize, k1: usize, k2: usize, k3: usize, tt: &mut [u64], z: &mut [u64]) {
    let words = size(n);
    debug_assert!(n & 63 != 0 && k3 < 64 && n - k3 >= 64 && words >= 5);
    assert_eq!(z.len(), words, "invalid reduced output length");
    assert!(tt.len() >= words * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);
    let w_n = words - 1;
    let s_n = n & 63;
    let mut pos = w_n;
    let mut t_high = tt[pos + w_n + 1];
    let mut t_low = tt[pos + w_n];
    loop {
        let t = (t_low >> s_n) | (t_high << (64 - s_n));
        tt[pos] ^= t ^ (t << k1) ^ (t << k2) ^ (t << k3);
        tt[pos + 1] ^= t >> (64 - k1) ^ t >> (64 - k2) ^ t >> (64 - k3);
        if pos == 0 {
            break;
        }
        pos -= 1;
        t_high = t_low;
        t_low = tt[pos + w_n];
    }
    z[..w_n].copy_from_slice(&tt[..w_n]);
    z[w_n] = tt[w_n] & ((1_u64 << s_n) - 1);
}

fn reduce_a_const<const N: usize, const SLACK: bool>(
    n: usize,
    k1: usize,
    k2: usize,
    k3: usize,
    tt: &[u64],
    z: &mut [u64],
) {
    debug_assert_eq!(size(n), N);
    debug_assert!(n & 63 != 0 && k3 < 64 && n - k3 >= 64);
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
        words[pos] ^= t ^ (t << k1) ^ (t << k2) ^ (t << k3);
        words[pos + 1] ^= t >> (64 - k1) ^ t >> (64 - k2) ^ t >> (64 - k3);
    }
    z.copy_from_slice(&words[..N]);
    z[N - 1] &= (1_u64 << s_n) - 1;
}

fn reduce_b(n: usize, k1: usize, k2: usize, k3: usize, tt: &mut [u64], z: &mut [u64]) {
    let words = size(n);
    debug_assert!(n & 63 != 0 && k2 >= 64 && n - k3 >= 64);
    assert_eq!(z.len(), words, "invalid reduced output length");
    assert!(tt.len() >= words * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);
    let w_n = words - 1;
    let s_n = n & 63;
    let taps = [(k1 >> 6, k1 & 63), (k2 >> 6, k2 & 63), (k3 >> 6, k3 & 63)];
    for pos in (0..=w_n).rev() {
        let t = (tt[pos + w_n] >> s_n) | (tt[pos + w_n + 1] << (64 - s_n));
        tt[pos] ^= t;
        for &(word, shift) in &taps {
            tt[pos + word] ^= t << shift;
            tt[pos + word + 1] ^= t >> (64 - shift);
        }
    }
    z[..w_n].copy_from_slice(&tt[..w_n]);
    z[w_n] = tt[w_n] & ((1_u64 << s_n) - 1);
}

fn reduce_d(n: usize, k1: usize, k2: usize, k3: usize, tt: &mut [u64], z: &mut [u64]) {
    let words = size(n);
    debug_assert!(n & 63 != 0 && k2 < 64 && k3 >= 64 && k3 & 63 != 0);
    assert_eq!(z.len(), words, "invalid reduced output length");
    assert!(tt.len() >= words * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);
    let w_n = words - 1;
    let s_n = n & 63;
    let w_k3 = k3 >> 6;
    let s_k3 = k3 & 63;
    for pos in (0..=w_n).rev() {
        let t = (tt[pos + w_n] >> s_n) | (tt[pos + w_n + 1] << (64 - s_n));
        tt[pos] ^= t ^ (t << k1) ^ (t << k2);
        tt[pos + 1] ^= t >> (64 - k1) ^ t >> (64 - k2);
        tt[pos + w_k3] ^= t << s_k3;
        tt[pos + w_k3 + 1] ^= t >> (64 - s_k3);
    }
    z[..w_n].copy_from_slice(&tt[..w_n]);
    z[w_n] = tt[w_n] & ((1_u64 << s_n) - 1);
}

fn reduce_e(n: usize, k1: usize, k2: usize, k3: usize, tt: &mut [u64], z: &mut [u64]) {
    let words = size(n);
    debug_assert!(n & 63 == 0 && n - k3 >= 64);
    assert_eq!(z.len(), words, "invalid reduced output length");
    assert!(tt.len() >= words * 2, "invalid extended input length");
    debug_assert_product_slack(n, tt);
    let taps = [(k1 >> 6, k1 & 63), (k2 >> 6, k2 & 63), (k3 >> 6, k3 & 63)];
    for pos in (0..words).rev() {
        let t = tt[pos + words];
        tt[pos] ^= t;
        for &(word, shift) in &taps {
            tt[pos + word] ^= t << shift;
            tt[pos + word + 1] ^= t >> (64 - shift);
        }
    }
    z.copy_from_slice(&tt[..words]);
}

#[cfg(test)]
mod tests {
    use super::super::bits::{product, size};
    use super::PentanomialReducer;

    type Shape = (u32, u32, u32, u32, fn(PentanomialReducer) -> bool);

    const SHAPES: [Shape; 18] = [
        (67, 1, 2, 3, |r| matches!(r, PentanomialReducer::A3(_))),
        (67, 1, 2, 5, |r| matches!(r, PentanomialReducer::C(_))),
        (100, 2, 5, 10, |r| matches!(r, PentanomialReducer::A4(_))),
        (131, 2, 3, 8, |r| matches!(r, PentanomialReducer::A5(_))),
        (163, 3, 6, 7, |r| matches!(r, PentanomialReducer::A6(_))),
        (200, 2, 5, 10, |r| matches!(r, PentanomialReducer::A7(_))),
        (233, 2, 5, 10, |r| matches!(r, PentanomialReducer::A8(_))),
        (283, 5, 7, 12, |r| matches!(r, PentanomialReducer::A(_))),
        (571, 2, 5, 10, |r| matches!(r, PentanomialReducer::A(_))),
        (257, 65, 70, 100, |r| matches!(r, PentanomialReducer::B(_))),
        (257, 64, 70, 100, |r| matches!(r, PentanomialReducer::C(_))),
        (100, 2, 5, 50, |r| matches!(r, PentanomialReducer::C(_))),
        (192, 64, 70, 80, |r| matches!(r, PentanomialReducer::C(_))),
        (257, 3, 5, 100, |r| matches!(r, PentanomialReducer::D(_))),
        (257, 3, 5, 128, |r| matches!(r, PentanomialReducer::C(_))),
        (192, 1, 5, 100, |r| matches!(r, PentanomialReducer::E(_))),
        (192, 1, 5, 150, |r| matches!(r, PentanomialReducer::C(_))),
        (320, 1, 65, 129, |r| matches!(r, PentanomialReducer::E(_))),
    ];

    #[test]
    fn each_shape_of_pentanomial_gets_the_reducer_bc_picks() {
        for (n, k1, k2, k3, expected) in SHAPES {
            assert!(
                expected(PentanomialReducer::new(n, k1, k2, k3)),
                "n = {n}, taps = ({k1}, {k2}, {k3})"
            );
        }
    }

    #[test]
    fn every_specialized_reducer_agrees_with_the_bitwise_fold() {
        for (n, k1, k2, k3, _) in SHAPES {
            let (n_, k1_, k2_, k3_) = (n as usize, k1 as usize, k2 as usize, k3 as usize);
            for seed in 1..=20 {
                let mut tt = product(n_, seed);
                let mut expected_tt = tt.clone();
                let mut z = alloc::vec![0; size(n_)];
                let mut expected = alloc::vec![0; size(n_)];
                PentanomialReducer::new(n, k1, k2, k3).reduce(&mut tt, &mut z);
                super::reduce_c(n_, k1_, k2_, k3_, &mut expected_tt, &mut expected);
                assert_eq!(
                    z, expected,
                    "n = {n}, taps = ({k1}, {k2}, {k3}), seed = {seed}"
                );
            }
        }
    }
}
