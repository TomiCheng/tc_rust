use crate::BinPolyError;
use crate::reduce::{Reducer, size};

/// The largest degree, as in BC's `BinPolys.Mul`.
pub(crate) const MAX_N: u32 = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinField {
    reducer: Reducer,
}

impl BinField {
    /// `x^n + x^k + 1`, `0 < k < n`, for `3 <= n <= 2^20`. The polynomial is not checked
    /// to be irreducible.
    pub fn trinomial(n: u32, k: u32) -> Result<Self, BinPolyError> {
        check_degree(n, 3)?;
        if k == 0 || k >= n {
            return Err(BinPolyError::InvalidTrinomialTap {
                n: n as usize,
                k: k as usize,
            });
        }
        Ok(Self {
            reducer: Reducer::trinomial(n, k),
        })
    }

    /// `x^n + x^k3 + x^k2 + x^k1 + 1`, `0 < k1 < k2 < k3 < n`, for `5 <= n <= 2^20`. The
    /// polynomial is not checked to be irreducible.
    pub fn pentanomial(n: u32, k1: u32, k2: u32, k3: u32) -> Result<Self, BinPolyError> {
        check_degree(n, 5)?;
        if k1 == 0 || k2 <= k1 || k3 <= k2 || k3 >= n {
            return Err(BinPolyError::InvalidPentanomialTaps {
                n: n as usize,
                k1: k1 as usize,
                k2: k2 as usize,
                k3: k3 as usize,
            });
        }
        Ok(Self {
            reducer: Reducer::pentanomial(n, k1, k2, k3),
        })
    }

    /// `x^n + 1`, for `1 <= n <= 2^20`: a ring, not a field.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn binomial(n: u32) -> Result<Self, BinPolyError> {
        check_degree(n, 1)?;
        Ok(Self {
            reducer: Reducer::binomial(n),
        })
    }

    /// The degree `n` of the modulus.
    pub fn n(&self) -> u32 {
        self.reducer.n()
    }

    /// The limbs of a reduced polynomial, `⌈n / 64⌉`.
    pub fn size(&self) -> usize {
        size(self.n() as usize)
    }
}

fn check_degree(n: u32, minimum: u32) -> Result<(), BinPolyError> {
    if n < minimum {
        return Err(BinPolyError::DegreeTooSmall {
            minimum: minimum as usize,
            actual: n as usize,
        });
    }
    if n > MAX_N {
        return Err(BinPolyError::DegreeTooLarge {
            maximum: MAX_N as usize,
            actual: n as usize,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BinField, MAX_N};
    use crate::BinPolyError;

    #[test]
    fn the_sec_moduli_are_accepted() {
        for (n, k) in [
            (113, 9),
            (131, 8),
            (193, 15),
            (233, 74),
            (239, 36),
            (409, 87),
        ] {
            assert!(BinField::trinomial(n, k).is_ok(), "n = {n}");
        }
        for (n, k1, k2, k3) in [
            (131, 2, 3, 8),
            (163, 3, 6, 7),
            (283, 5, 7, 12),
            (571, 2, 5, 10),
        ] {
            assert!(BinField::pentanomial(n, k1, k2, k3).is_ok(), "n = {n}");
        }
    }

    #[test]
    fn a_degree_out_of_range_is_refused() {
        assert_eq!(
            BinField::trinomial(2, 1),
            Err(BinPolyError::DegreeTooSmall {
                minimum: 3,
                actual: 2
            })
        );
        assert_eq!(
            BinField::pentanomial(4, 1, 2, 3),
            Err(BinPolyError::DegreeTooSmall {
                minimum: 5,
                actual: 4
            })
        );
        assert_eq!(
            BinField::trinomial(MAX_N + 1, 1),
            Err(BinPolyError::DegreeTooLarge {
                maximum: MAX_N as usize,
                actual: MAX_N as usize + 1
            })
        );
        assert!(BinField::trinomial(MAX_N, 1).is_ok());
        assert!(BinField::binomial(0).is_err() && BinField::binomial(1).is_ok());
    }

    #[test]
    fn the_size_is_the_degree_rounded_up_to_whole_limbs() {
        for (field, n, size) in [
            (BinField::trinomial(63, 1), 63, 1),
            (BinField::trinomial(64, 1), 64, 1),
            (BinField::trinomial(233, 74), 233, 4),
            (BinField::pentanomial(163, 3, 6, 7), 163, 3),
            (BinField::pentanomial(571, 2, 5, 10), 571, 9),
            (BinField::binomial(128), 128, 2),
            (BinField::binomial(129), 129, 3),
        ] {
            let field = field.unwrap();
            assert_eq!((field.n(), field.size()), (n, size), "n = {n}");
        }
    }

    #[test]
    fn taps_out_of_order_or_range_are_refused() {
        for k in [0, 163, 200] {
            assert_eq!(
                BinField::trinomial(163, k),
                Err(BinPolyError::InvalidTrinomialTap {
                    n: 163,
                    k: k as usize
                })
            );
        }
        for (k1, k2, k3) in [(0, 6, 7), (6, 3, 7), (3, 7, 7), (3, 6, 163)] {
            assert!(
                matches!(
                    BinField::pentanomial(163, k1, k2, k3),
                    Err(BinPolyError::InvalidPentanomialTaps { .. })
                ),
                "taps = ({k1}, {k2}, {k3})"
            );
        }
    }
}
