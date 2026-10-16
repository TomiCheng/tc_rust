use crate::BinField;
use tc_zeroize::Zeroize;

/// BC's `ItohTsujiiInv.Invert`: `z = x^(2^n - 2)`, which is `x⁻¹` for `x != 0` and `0` for
/// `x = 0`, by an addition chain on `n - 1`. Meaningful only for an irreducible modulus.
/// `b` and `t` are scratch of the field's size, wiped on return. The chain depends on `n`
/// alone, so it is as constant time as the field's multiplier.
pub(crate) fn invert(field: &BinField, x: &[u64], z: &mut [u64], b: &mut [u64], t: &mut [u64]) {
    // b holds a_j = x^(2^j - 1), j the run of one bits so far.
    b.copy_from_slice(x);
    let e = field.n() as usize - 1;
    let mut j = 1;
    for i in (0..e.ilog2()).rev() {
        // a_2j = (a_j)^(2^j) · a_j; z is free until the end.
        field.square_n(b, j, t);
        field.multiply(b, t, z);
        b.copy_from_slice(z);
        j *= 2;

        if e >> i & 1 == 1 {
            // a_(j+1) = (a_j)^2 · x
            field.square(b, t);
            field.multiply(t, x, b);
            j += 1;
        }
    }
    debug_assert_eq!(j, e);
    field.square(b, z);
    b.zeroize();
    t.zeroize();
}

#[cfg(test)]
mod tests {
    use super::invert;
    use crate::BinField;

    fn inverse(field: &BinField, x: &[u64]) -> alloc::vec::Vec<u64> {
        let size = x.len();
        let (mut z, mut b, mut t) = (
            alloc::vec![0; size],
            alloc::vec![0; size],
            alloc::vec![0; size],
        );
        invert(field, x, &mut z, &mut b, &mut t);
        assert!(b.iter().chain(&t).all(|&w| w == 0));
        z
    }

    #[test]
    fn the_aes_field_inverts_0x53_to_0xca() {
        let field = BinField::pentanomial(8, 1, 3, 4).unwrap();
        assert_eq!(inverse(&field, &[0x53]), [0xCA]);
    }

    #[test]
    fn a_value_times_its_inverse_is_one_and_zero_stays_zero() {
        let mut state = 0x1A70_75B1_1A70_75B1_u64;
        for field in [
            BinField::pentanomial(8, 1, 3, 4).unwrap(),
            BinField::pentanomial(128, 1, 2, 7).unwrap(),
            BinField::pentanomial(163, 3, 6, 7).unwrap(),
            BinField::trinomial(233, 74).unwrap(),
            BinField::pentanomial(283, 5, 7, 12).unwrap(),
            BinField::trinomial(409, 87).unwrap(),
            BinField::pentanomial(571, 2, 5, 10).unwrap(),
        ] {
            let (n, size) = (field.n(), field.size());
            let mut one = alloc::vec![0; size];
            one[0] = 1;
            assert_eq!(inverse(&field, &alloc::vec![0; size]), alloc::vec![0; size]);
            assert_eq!(inverse(&field, &one), one, "n = {n}");

            for _ in 0..4 {
                let mut x: alloc::vec::Vec<u64> = (0..size)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state
                    })
                    .collect();
                if n & 63 != 0 {
                    x[size - 1] &= (1 << (n & 63)) - 1;
                }
                let mut product = alloc::vec![0; size];
                field.multiply(&x, &inverse(&field, &x), &mut product);
                assert_eq!(product, one, "n = {n}");
            }
        }
    }
}
