use super::bits::{bit_value, debug_assert_product_slack, mask_top, size, xor_bit_value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BinomialReducer {
    /// `n % 64 != 0`: the result has a partial top limb.
    Unaligned { n: u32 },
    /// `n % 64 == 0`: the high limbs fold straight onto the low ones.
    Aligned { n: u32 },
}

impl BinomialReducer {
    /// Picks the reduction for `x^n + 1`, as BC's `BinomialReduce.Create` does.
    pub(crate) fn new(n: u32) -> Self {
        if n & 63 == 0 {
            Self::Aligned { n }
        } else {
            Self::Unaligned { n }
        }
    }

    pub(crate) fn n(&self) -> u32 {
        match *self {
            Self::Unaligned { n } | Self::Aligned { n } => n,
        }
    }

    /// Reduces the product `tt`, of `2 * size(n)` words, into `z`, of `size(n)` words.
    /// `tt` is scratch and is left changed.
    pub(crate) fn reduce(&self, tt: &mut [u64], z: &mut [u64]) {
        let n = self.n() as usize;
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
            // x^n = 1 bit by bit; BC splices whole words here.
            Self::Unaligned { .. } => {
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

#[cfg(test)]
mod tests {
    use super::super::bits::{bit_value, product, size};
    use super::BinomialReducer;

    #[test]
    fn x_to_the_n_folds_onto_one_at_every_alignment() {
        for n in [64, 128, 192, 65, 100, 127, 163, 257, 409] {
            assert_eq!(
                matches!(
                    BinomialReducer::new(n as u32),
                    BinomialReducer::Aligned { .. }
                ),
                n % 64 == 0
            );
            for seed in 1..=20 {
                let mut tt = product(n, seed);
                let expected: alloc::vec::Vec<u64> = (0..size(n))
                    .map(|word| {
                        (0..64)
                            .map(|bit| word * 64 + bit)
                            .filter(|&i| i < n)
                            .fold(0, |z, i| {
                                z | (bit_value(&tt, i) ^ bit_value(&tt, i + n)) << (i & 63)
                            })
                    })
                    .collect();
                let mut z = alloc::vec![0; size(n)];
                BinomialReducer::new(n as u32).reduce(&mut tt, &mut z);
                assert_eq!(z, expected, "n = {n}, seed = {seed}");
            }
        }
    }
}
