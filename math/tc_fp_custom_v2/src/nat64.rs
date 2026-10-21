// Products on little-endian 64-bit limbs with u128 words, where BC multiplies 32-bit ones: at
// 384 bits and up they cost more than the reductions, which stay BC's. Constant time, as
// `nat` is.

// BC's `Nat.Mul` on 64-bit limbs: the schoolbook product, on M = 2N limbs.
pub(crate) fn mul<const N: usize, const M: usize>(x: &[u64; N], y: &[u64; N]) -> [u64; M] {
    const { assert!(M == 2 * N) };
    let mut zz = [0; M];
    for (i, &xi) in x.iter().enumerate() {
        let xi = u128::from(xi);
        let mut c = 0u128;
        for (zj, &yj) in zz[i..i + N].iter_mut().zip(y) {
            c += xi * u128::from(yj) + u128::from(*zj);
            *zj = c as u64;
            c >>= 64;
        }
        zz[i + N] = c as u64;
    }
    zz
}

// BC's `Nat.Square` on 64-bit limbs: the cross products once, doubled by a shift, then the
// squares of the limbs added; on M = 2N limbs.
pub(crate) fn square<const N: usize, const M: usize>(x: &[u64; N]) -> [u64; M] {
    const { assert!(M == 2 * N) };
    let mut zz = [0; M];
    for i in 0..N - 1 {
        let xi = u128::from(x[i]);
        let mut c = 0u128;
        for (zk, &xj) in zz[2 * i + 1..i + N].iter_mut().zip(&x[i + 1..]) {
            c += xi * u128::from(xj) + u128::from(*zk);
            *zk = c as u64;
            c >>= 64;
        }
        zz[i + N] = c as u64;
    }
    let mut top = 0;
    for z in &mut zz {
        let next = *z >> 63;
        *z = (*z << 1) | top;
        top = next;
    }
    let mut c = 0u128;
    for (pair, &xi) in zz.chunks_exact_mut(2).zip(x) {
        let square = u128::from(xi) * u128::from(xi);
        c += u128::from(pair[0]) + u128::from(square as u64);
        pair[0] = c as u64;
        c >>= 64;
        c += u128::from(pair[1]) + (square >> 64);
        pair[1] = c as u64;
        c >>= 64;
    }
    zz
}

// The N 32-bit limbs of x paired into H = ceil(N / 2).
pub(crate) fn from_u32<const N: usize, const H: usize>(x: &[u32; N]) -> [u64; H] {
    const { assert!(H == N.div_ceil(2)) };
    core::array::from_fn(|i| {
        let high = x.get(2 * i + 1).map_or(0, |&word| u64::from(word));
        u64::from(x[2 * i]) | (high << 32)
    })
}

// The low N 32-bit halves of the H limbs of x.
pub(crate) fn to_u32<const H: usize, const N: usize>(x: &[u64; H]) -> [u32; N] {
    const { assert!(H == N.div_ceil(2)) };
    core::array::from_fn(|i| (x[i / 2] >> (32 * (i % 2))) as u32)
}

#[cfg(test)]
mod tests {
    use super::{from_u32, mul, square, to_u32};
    use crate::nat;

    // xorshift64 words.
    fn words<const N: usize>(state: &mut u64) -> [u32; N] {
        core::array::from_fn(|_| {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as u32
        })
    }

    #[test]
    fn products_and_squares_match_the_32_bit_schoolbook_product() {
        let mut state = 0x6464_0384;
        let mut edges = [[0; 12], [u32::MAX; 12], [0; 12]];
        edges[2][6] = 1;
        for i in 0..103 {
            let x = edges.get(i).copied().unwrap_or_else(|| words(&mut state));
            let y: [u32; 12] = words(&mut state);
            let (x64, y64) = (from_u32::<12, 6>(&x), from_u32::<12, 6>(&y));
            let product: [u32; 24] = nat::mul(&x, &y);
            assert_eq!(to_u32::<12, 24>(&mul::<6, 12>(&x64, &y64)), product);
            let squared: [u32; 24] = nat::mul(&x, &x);
            assert_eq!(to_u32::<12, 24>(&square::<6, 12>(&x64)), squared);
        }
    }

    #[test]
    fn an_odd_count_of_32_bit_limbs_round_trips() {
        let mut state = 0x6464_0521;
        let x: [u32; 17] = words(&mut state);
        let x64 = from_u32::<17, 9>(&x);
        assert_eq!(x64[8], u64::from(x[16]));
        assert_eq!(to_u32::<9, 17>(&x64), x);
    }
}
