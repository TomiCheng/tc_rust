use super::binomial::BinomialReducer;
use super::pentanomial::PentanomialReducer;
use super::trinomial::TrinomialReducer;

/// The reduction modulo `x^n + 1`, a trinomial or a pentanomial, chosen at construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Reducer {
    Binomial(BinomialReducer),
    Trinomial(TrinomialReducer),
    Pentanomial(PentanomialReducer),
}

impl Reducer {
    #[allow(dead_code)]
    pub(crate) fn binomial(n: u32) -> Self {
        Self::Binomial(BinomialReducer::new(n))
    }

    pub(crate) fn trinomial(n: u32, k: u32) -> Self {
        Self::Trinomial(TrinomialReducer::new(n, k))
    }

    pub(crate) fn pentanomial(n: u32, k1: u32, k2: u32, k3: u32) -> Self {
        Self::Pentanomial(PentanomialReducer::new(n, k1, k2, k3))
    }

    pub(crate) fn n(&self) -> u32 {
        match self {
            Self::Binomial(reducer) => reducer.n(),
            Self::Trinomial(reducer) => reducer.n(),
            Self::Pentanomial(reducer) => reducer.n(),
        }
    }

    /// Reduces the product `tt`, of `2 * size(n)` words, into `z`, of `size(n)` words.
    /// `tt` is scratch and is left changed.
    pub(crate) fn reduce(&self, tt: &mut [u64], z: &mut [u64]) {
        match self {
            Self::Binomial(reducer) => reducer.reduce(tt, z),
            Self::Trinomial(reducer) => reducer.reduce(tt, z),
            Self::Pentanomial(reducer) => reducer.reduce(tt, z),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::binomial::BinomialReducer;
    use super::super::bits::{product, size};
    use super::super::pentanomial::PentanomialReducer;
    use super::super::trinomial::TrinomialReducer;
    use super::Reducer;

    type Reduce = fn(&mut [u64], &mut [u64]);

    #[test]
    fn each_kind_reduces_as_its_own_reducer_does() {
        let cases: [(usize, Reducer, Reduce); 3] = [
            (
                163,
                Reducer::binomial(163),
                |tt: &mut [u64], z: &mut [u64]| BinomialReducer::new(163).reduce(tt, z),
            ),
            (
                233,
                Reducer::trinomial(233, 74),
                |tt: &mut [u64], z: &mut [u64]| TrinomialReducer::new(233, 74).reduce(tt, z),
            ),
            (
                283,
                Reducer::pentanomial(283, 5, 7, 12),
                |tt: &mut [u64], z: &mut [u64]| {
                    PentanomialReducer::new(283, 5, 7, 12).reduce(tt, z)
                },
            ),
        ];
        for (n, reducer, direct) in cases {
            let mut tt = product(n, 7);
            let mut direct_tt = tt.clone();
            let mut z = alloc::vec![0; size(n)];
            let mut expected = alloc::vec![0; size(n)];
            reducer.reduce(&mut tt, &mut z);
            direct(&mut direct_tt, &mut expected);
            assert_eq!(z, expected, "n = {n}");
        }
    }
}
