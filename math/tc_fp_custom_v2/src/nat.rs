// BC's `Nat`: unsigned integers on little-endian 32-bit limbs, the width fixed by the array,
// and the arithmetic modulo a prime p of that width. Constant time: no branch or index
// depends on a value, only on the widths.

use tc_zeroize::Zeroize;

pub(crate) fn add<const N: usize>(x: &[u32; N], y: &[u32; N]) -> ([u32; N], u32) {
    let mut z = [0; N];
    let mut c = 0u64;
    for i in 0..N {
        c += u64::from(x[i]) + u64::from(y[i]);
        z[i] = c as u32;
        c >>= 32;
    }
    (z, c as u32)
}

// The difference and the borrow, 1 when x < y.
pub(crate) fn sub<const N: usize>(x: &[u32; N], y: &[u32; N]) -> ([u32; N], u32) {
    let mut z = [0; N];
    let mut c = 0i64;
    for i in 0..N {
        c += i64::from(x[i]) - i64::from(y[i]);
        z[i] = c as u32;
        c >>= 32;
    }
    (z, (c & 1) as u32)
}

// BC's `Nat.Mul`: the schoolbook product, on M = 2N limbs.
pub(crate) fn mul<const N: usize, const M: usize>(x: &[u32; N], y: &[u32; N]) -> [u32; M] {
    const { assert!(M == 2 * N) };
    let mut zz = [0; M];
    for (i, &xi) in x.iter().enumerate() {
        let xi = u64::from(xi);
        let mut c = 0u64;
        for (zj, &yj) in zz[i..i + N].iter_mut().zip(y) {
            c += xi * u64::from(yj) + u64::from(*zj);
            *zj = c as u32;
            c >>= 32;
        }
        zz[i + N] = c as u32;
    }
    zz
}

// BC's `Nat.Square`: the squares of the words, halved, then the cross products added once,
// and the whole shifted up a bit to double them; on M = 2N limbs.
pub(crate) fn square<const N: usize, const M: usize>(x: &[u32; N]) -> [u32; M] {
    const { assert!(M == 2 * N) };
    let mut zz = [0; M];
    let mut c = 0u32;
    for j in (0..N).rev() {
        let x_val = u64::from(x[j]);
        let p = x_val * x_val;
        zz[2 * j + 1] = (c << 31) | (p >> 33) as u32;
        zz[2 * j] = (p >> 1) as u32;
        c = p as u32;
    }
    let mut d = 0u64;
    for i in 1..N {
        d += u64::from(square_word_add_to(x, i, &mut zz));
        for pos in [2 * i, 2 * i + 1] {
            d += u64::from(zz[pos]);
            zz[pos] = d as u32;
            d >>= 32;
        }
    }
    debug_assert_eq!(d, 0);
    shift_up_bit(&mut zz, x[0] << 31);
    zz
}

// BC's `Nat.SquareWordAddTo`: z[pos..2pos] += x[pos]·x[..pos], returning the carry.
fn square_word_add_to<const N: usize, const M: usize>(
    x: &[u32; N],
    pos: usize,
    z: &mut [u32; M],
) -> u32 {
    let x_val = u64::from(x[pos]);
    let mut c = 0u64;
    for (zi, &xi) in z[pos..2 * pos].iter_mut().zip(&x[..pos]) {
        c += x_val * u64::from(xi) + u64::from(*zi);
        *zi = c as u32;
        c >>= 32;
    }
    c as u32
}

// BC's `Nat.ShiftUpBit`: z <- 2z + the top bit of c.
fn shift_up_bit<const M: usize>(z: &mut [u32; M], mut c: u32) {
    for limb in z.iter_mut() {
        let next = *limb;
        *limb = (next << 1) | (c >> 31);
        c = next;
    }
}

// BC's `Nat384.Mul` for N = 2H limbs, one Karatsuba step on halves of H:
// x·y = xl·yl·(1 + B) + xh·yh·(B + B²) - (xh - xl)(yh - yl)·B for B = 2^(32H). BC branches on
// the signs of the two differences; here they are masked.
pub(crate) fn karatsuba_mul<const H: usize, const N: usize, const M: usize>(
    x: &[u32; N],
    y: &[u32; N],
) -> [u32; M] {
    const { assert!(N == 2 * H && M == 4 * H) };
    let (mut xl, mut xh) = halves::<H, N>(x);
    let (mut yl, mut yh) = halves::<H, N>(y);
    let mut low: [u32; N] = mul(&xl, &yl);
    let mut high: [u32; N] = mul(&xh, &yh);
    let (mut dx, x_borrow) = abs_diff(&xh, &xl);
    let (mut dy, y_borrow) = abs_diff(&yh, &yl);
    let mut middle: [u32; N] = mul(&dx, &dy);
    let zz = karatsuba_combine::<H, N, M>(&low, &high, &middle, x_borrow ^ y_borrow);
    for limbs in [&mut xl, &mut xh, &mut yl, &mut yh, &mut dx, &mut dy] {
        limbs.zeroize();
    }
    for limbs in [&mut low, &mut high, &mut middle] {
        limbs.zeroize();
    }
    zz
}

// BC's `Nat384.Square`: `karatsuba_mul` with y = x, whose middle product is a square.
pub(crate) fn karatsuba_square<const H: usize, const N: usize, const M: usize>(
    x: &[u32; N],
) -> [u32; M] {
    const { assert!(N == 2 * H && M == 4 * H) };
    let (mut xl, mut xh) = halves::<H, N>(x);
    let mut low: [u32; N] = square(&xl);
    let mut high: [u32; N] = square(&xh);
    let (mut dx, _) = abs_diff(&xh, &xl);
    let mut middle: [u32; N] = square(&dx);
    let zz = karatsuba_combine::<H, N, M>(&low, &high, &middle, 0);
    for limbs in [&mut xl, &mut xh, &mut dx] {
        limbs.zeroize();
    }
    for limbs in [&mut low, &mut high, &mut middle] {
        limbs.zeroize();
    }
    zz
}

fn halves<const H: usize, const N: usize>(x: &[u32; N]) -> ([u32; H], [u32; H]) {
    (
        core::array::from_fn(|i| x[i]),
        core::array::from_fn(|i| x[H + i]),
    )
}

// |a - b|, and 1 when a < b.
fn abs_diff<const H: usize>(a: &[u32; H], b: &[u32; H]) -> ([u32; H], u32) {
    let (d, borrow) = sub(a, b);
    let flip = mask(borrow);
    let mut z = [0; H];
    let mut c = u64::from(borrow);
    for i in 0..H {
        c += u64::from(d[i] ^ flip);
        z[i] = c as u32;
        c >>= 32;
    }
    (z, borrow)
}

// The sums of BC's `Nat384.Mul` after its three products; the middle one is added when
// `add` is 1 and subtracted when it is 0, through its complement, without a branch.
fn karatsuba_combine<const H: usize, const N: usize, const M: usize>(
    low: &[u32; N],
    high: &[u32; N],
    middle: &[u32; N],
    add: u32,
) -> [u32; M] {
    let mut zz = [0; M];
    zz[..N].copy_from_slice(low);
    zz[N..].copy_from_slice(high);

    // BC's `AddToEachOther(zz, H, zz, 2H)`.
    let mut c = 0u64;
    for i in 0..H {
        c += u64::from(zz[H + i]) + u64::from(zz[2 * H + i]);
        zz[H + i] = c as u32;
        zz[2 * H + i] = c as u32;
        c >>= 32;
    }
    let mut c3 = c as u32;
    // BC's `AddTo(zz, 0, zz, H, 0)`, and `AddTo(zz, 3H, zz, 2H, ...)` with its carry.
    let mut c = 0u64;
    for i in 0..H {
        c += u64::from(zz[i]) + u64::from(zz[H + i]);
        zz[H + i] = c as u32;
        c >>= 32;
    }
    let mut c = u64::from(c3) + c;
    for i in 0..H {
        c += u64::from(zz[3 * H + i]) + u64::from(zz[2 * H + i]);
        zz[2 * H + i] = c as u32;
        c >>= 32;
    }
    c3 = c3.wrapping_add(c as u32);

    // zz[H..3H] ± middle, the carry or the borrow going into c3.
    let complement = mask(add ^ 1);
    let mut c = u64::from(complement & 1);
    for i in 0..N {
        c += u64::from(zz[H + i]) + u64::from(middle[i] ^ complement);
        zz[H + i] = c as u32;
        c >>= 32;
    }
    c3 = c3.wrapping_add(c as u32).wrapping_add(complement);

    // BC's `AddWordAt(4H, c3, zz, 3H)`.
    let mut c = u64::from(c3);
    for limb in &mut zz[3 * H..] {
        c += u64::from(*limb);
        *limb = c as u32;
        c >>= 32;
    }
    zz
}

// All ones for 1, zero for 0.
pub(crate) fn mask(bit: u32) -> u32 {
    bit.wrapping_neg()
}

// `b` where `mask` is all ones, `a` where it is zero.
pub(crate) fn select<const N: usize>(mask: u32, a: &[u32; N], b: &[u32; N]) -> [u32; N] {
    core::array::from_fn(|i| a[i] ^ (mask & (a[i] ^ b[i])))
}

// 1 when x is zero, else 0.
pub(crate) fn is_zero<const N: usize>(x: &[u32; N]) -> u32 {
    let acc = x.iter().fold(0, |acc, &limb| acc | limb);
    ((acc | acc.wrapping_neg()) >> 31) ^ 1
}

// z mod p, for z + carry·2^(32N) below 2p.
pub(crate) fn reduce_once<const N: usize>(z: &[u32; N], carry: u32, p: &[u32; N]) -> [u32; N] {
    let (t, borrow) = sub(z, p);
    select(mask(carry | (borrow ^ 1)), z, &t)
}

// z + x·(2^(32N) mod p) mod p, where the coefficients of 2^(32N) mod p are 1, -1 or 0 by
// limb, as for the Solinas primes; BC's `Reduce32`, which skips the carries it can.
pub(crate) fn fold<const N: usize>(
    z: &[u32; N],
    x: u32,
    coefficients: &[i64; N],
    p: &[u32; N],
) -> [u32; N] {
    let mut out = [0; N];
    let mut cc = 0i64;
    for i in 0..N {
        cc += i64::from(z[i]) + coefficients[i] * i64::from(x);
        out[i] = cc as u32;
        cc >>= 32;
    }
    debug_assert!(cc == 0 || cc == 1);
    reduce_once(&out, cc as u32, p)
}

// BC's `Mul33Add` and `Mul33DWordAdd`, for p = 2^(32N) - 2^32 - w: H·2^(32N) + L folds to
// L + H·(2^32 + w), twice, the second time for the few bits the first leaves above 2^(32N),
// then one masked subtraction where BC branches.
pub(crate) fn reduce33<const N: usize, const M: usize>(
    xx: &[u32; M],
    w: u64,
    p: &[u32; N],
) -> [u32; N] {
    const { assert!(M == 2 * N && N >= 3) };
    let mut z = [0; N];
    let mut c = 0u64;
    for i in 0..N {
        let shifted = if i == 0 { 0 } else { u64::from(xx[N - 1 + i]) };
        c += u64::from(xx[i]) + u64::from(xx[N + i]) * w + shifted;
        z[i] = c as u32;
        c >>= 32;
    }
    let t = c + u64::from(xx[M - 1]);

    let low = t * w;
    let mut cc = u64::from(z[0]) + (low & 0xFFFF_FFFF);
    z[0] = cc as u32;
    cc >>= 32;
    cc += u64::from(z[1]) + (low >> 32) + (t & 0xFFFF_FFFF);
    z[1] = cc as u32;
    cc >>= 32;
    cc += u64::from(z[2]) + (t >> 32);
    z[2] = cc as u32;
    cc >>= 32;
    for limb in &mut z[3..] {
        cc += u64::from(*limb);
        *limb = cc as u32;
        cc >>= 32;
    }
    debug_assert!(cc == 0 || cc == 1);
    reduce_once(&z, cc as u32, p)
}

pub(crate) fn add_mod<const N: usize>(x: &[u32; N], y: &[u32; N], p: &[u32; N]) -> [u32; N] {
    let (z, carry) = add(x, y);
    reduce_once(&z, carry, p)
}

pub(crate) fn sub_mod<const N: usize>(x: &[u32; N], y: &[u32; N], p: &[u32; N]) -> [u32; N] {
    let (z, borrow) = sub(x, y);
    let correction = select(mask(borrow), &[0; N], p);
    add(&z, &correction).0
}

// The value of the big-endian `bytes`, of at most 4N, modulo p, word by word from the top.
pub(crate) fn reduce_be<const N: usize>(
    bytes: &[u8],
    p: &[u32; N],
    multiply: fn(&[u32; N], &[u32; N]) -> [u32; N],
) -> [u32; N] {
    let mut shift = [0; N];
    shift[1] = 1;
    let head = bytes.len() % 4;
    let words = (head != 0)
        .then(|| be_word(&bytes[..head]))
        .into_iter()
        .chain(bytes[head..].chunks(4).map(be_word));
    let mut z = [0; N];
    for word in words {
        let mut low = [0; N];
        low[0] = word;
        z = add_mod(&multiply(&z, &shift), &low, p);
    }
    z
}

fn be_word(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0, |word, &byte| (word << 8) | u32::from(byte))
}

// The big-endian `bytes`, of at most 4N.
pub(crate) fn from_be<const N: usize>(bytes: &[u8]) -> [u32; N] {
    debug_assert!(bytes.len() <= 4 * N);
    let mut z = [0; N];
    for (i, &byte) in bytes.iter().rev().enumerate() {
        z[i / 4] |= u32::from(byte) << (8 * (i % 4));
    }
    z
}

// Fills `output`, of at most 4N bytes, with the low bytes of x, big-endian.
pub(crate) fn to_be<const N: usize>(x: &[u32; N], output: &mut [u8]) {
    debug_assert!(output.len() <= 4 * N);
    for (i, byte) in output.iter_mut().rev().enumerate() {
        *byte = (x[i / 4] >> (8 * (i % 4))) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        add, from_be, is_zero, karatsuba_mul, karatsuba_square, mul, reduce_once, select, square,
        sub, sub_mod, to_be,
    };

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
    fn squares_and_karatsuba_products_match_the_schoolbook_product() {
        let mut state = 0x5A5A_0384;
        let mut edges = [[0; 12], [u32::MAX; 12], [0; 12]];
        edges[2][6] = 1;
        for i in 0..103 {
            let x = edges.get(i).copied().unwrap_or_else(|| words(&mut state));
            let y: [u32; 12] = words(&mut state);
            let expected: [u32; 24] = mul(&x, &y);
            assert_eq!(karatsuba_mul::<6, 12, 24>(&x, &y), expected);
            assert_eq!(karatsuba_mul::<6, 12, 24>(&y, &x), expected);
            let squared: [u32; 24] = mul(&x, &x);
            assert_eq!(karatsuba_square::<6, 12, 24>(&x), squared);
            assert_eq!(square::<12, 24>(&x), squared);
            let low: [u32; 8] = core::array::from_fn(|i| x[i]);
            let low_squared: [u32; 16] = mul(&low, &low);
            assert_eq!(square::<8, 16>(&low), low_squared);
        }
    }

    #[test]
    fn carries_and_borrows_cross_every_limb() {
        let max = [u32::MAX; 3];
        assert_eq!(add(&max, &[1, 0, 0]), ([0; 3], 1));
        assert_eq!(sub(&[0; 3], &[1, 0, 0]), (max, 1));
        assert_eq!(sub(&[5, 0, 0], &[3, 0, 0]), ([2, 0, 0], 0));
        let square: [u32; 6] = mul(&max, &max);
        // (2^96 - 1)^2 = 2^192 - 2^97 + 1
        assert_eq!(square, [1, 0, 0, u32::MAX - 1, u32::MAX, u32::MAX]);
    }

    #[test]
    fn masks_select_and_test_for_zero() {
        assert_eq!(select(0, &[1, 2], &[3, 4]), [1, 2]);
        assert_eq!(select(u32::MAX, &[1, 2], &[3, 4]), [3, 4]);
        assert_eq!(
            (is_zero(&[0, 0]), is_zero(&[0, 1]), is_zero(&[1 << 31, 0])),
            (1, 0, 0)
        );
    }

    #[test]
    fn reduction_and_subtraction_wrap_by_the_modulus() {
        let p = [7, 0];
        assert_eq!(reduce_once(&[8, 0], 0, &p), [1, 0]);
        assert_eq!(reduce_once(&[6, 0], 0, &p), [6, 0]);
        assert_eq!(reduce_once(&[1, 0], 1, &[u32::MAX, u32::MAX]), [2, 0]);
        assert_eq!(sub_mod(&[2, 0], &[5, 0], &p), [4, 0]);
    }

    #[test]
    fn bytes_round_trip_big_endian() {
        let x: [u32; 2] = from_be(&[1, 2, 3, 4, 5]);
        assert_eq!(x, [0x0203_0405, 0x01]);
        let mut out = [0; 5];
        to_be(&x, &mut out);
        assert_eq!(out, [1, 2, 3, 4, 5]);
    }
}
