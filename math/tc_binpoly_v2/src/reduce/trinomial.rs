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
}

#[cfg(test)]
mod tests {
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
}
