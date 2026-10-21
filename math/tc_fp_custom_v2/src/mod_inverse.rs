// BC's `Mod.ModOddInverse`: the inverse modulo an odd m by the safegcd of Bernstein and Yang,
// in its "half delta" variant, on signed 30-bit digits, L of them for the bits of m. Constant
// time: the number of divsteps follows the width of m alone, and every step is masked.

use tc_zeroize::Zeroize;

const M30: i32 = 0x3FFF_FFFF;

// x^-1 mod m, and 1 when it exists, 0 when it does not, as for x = 0.
pub(crate) fn mod_odd_inverse<const N: usize, const L: usize>(
    m: &[u32; N],
    x: &[u32; N],
) -> ([u32; N], u32) {
    debug_assert!(m[0] & 1 == 1 && m[N - 1] != 0);
    let bits = 32 * N - m[N - 1].leading_zeros() as usize;
    debug_assert_eq!(L, bits.div_ceil(30));

    let mut t = [0; 4];
    let mut d = [0; L];
    let mut e = [0; L];
    e[0] = 1;
    let mut g = encode30::<N, L>(bits, x);
    let modulus = encode30::<N, L>(bits, m);
    let mut f = modulus;

    let mut theta = 0;
    let m0_inv32 = inverse32(modulus[0] as u32) as i32;
    let max_divsteps = maximum_hd_divsteps(bits);
    let mut divsteps = 0;
    while divsteps < max_divsteps {
        theta = hd_divsteps30(theta, f[0], g[0], &mut t);
        update_de30(&mut d, &mut e, &t, m0_inv32, &modulus);
        update_fg30(&mut f, &mut g, &t);
        divsteps += 30;
    }

    let sign_f = f[L - 1] >> 31;
    cnegate30(sign_f, &mut f);
    cnormalize30(sign_f, &mut d, &modulus);
    let z = decode30::<N, L>(bits, &d);
    let ok = equal_to(&f, 1) & equal_to(&g, 0);

    t.zeroize();
    d.zeroize();
    e.zeroize();
    f.zeroize();
    g.zeroize();
    (z, ok)
}

// d^-1 mod 2^32 for an odd d, by Newton's iteration.
fn inverse32(d: u32) -> u32 {
    debug_assert!(d & 1 == 1);
    let mut x = d;
    for _ in 0..4 {
        x = x.wrapping_mul(2u32.wrapping_sub(d.wrapping_mul(x)));
    }
    debug_assert_eq!(d.wrapping_mul(x), 1);
    x
}

fn maximum_hd_divsteps(bits: usize) -> usize {
    ((150_964 * bits as u64 + 99_243) >> 16) as usize
}

// 30 divsteps on the low digits of f and g, the transition matrix scaled by 2^30 into t.
fn hd_divsteps30(mut theta: i32, f0: i32, g0: i32, t: &mut [i32; 4]) -> i32 {
    let (mut u, mut v, mut q, mut r) = (1i32 << 30, 0i32, 0i32, 1i32 << 30);
    let (mut f, mut g) = (f0, g0);
    for _ in 0..30 {
        debug_assert!(f & 1 == 1);
        let c1 = theta >> 31;
        let c2 = -(g & 1);
        let (x, y, z) = (f ^ c1, u ^ c1, v ^ c1);
        g = g.wrapping_sub(x & c2);
        q = q.wrapping_sub(y & c2);
        r = r.wrapping_sub(z & c2);
        let c3 = c2 & !c1;
        theta = (theta ^ c3).wrapping_add(1);
        f = f.wrapping_add(g & c3);
        u = u.wrapping_add(q & c3);
        v = v.wrapping_add(r & c3);
        g >>= 1;
        q >>= 1;
        r >>= 1;
    }
    *t = [u, v, q, r];
    theta
}

// (d, e) <- t繚(d, e) / 2^30 mod m, from (-2m, m) back into (-2m, m).
fn update_de30<const L: usize>(
    d: &mut [i32; L],
    e: &mut [i32; L],
    t: &[i32; 4],
    m0_inv32: i32,
    m: &[i32; L],
) {
    let [u, v, q, r] = *t;
    let wide = |a: i32, b: i32| i64::from(a) * i64::from(b);

    // A negative d or e counts as d + m or e + m, by adding u, v (q, r) into md (me).
    let sd = d[L - 1] >> 31;
    let se = e[L - 1] >> 31;
    let mut md = (u & sd) + (v & se);
    let mut me = (q & sd) + (r & se);

    let (di, ei) = (d[0], e[0]);
    let mut cd = wide(u, di) + wide(v, ei);
    let mut ce = wide(q, di) + wide(r, ei);

    // Less a term in [0, 2^30) that clears the low 30 bits, for an exact division by 2^30.
    md -= m0_inv32.wrapping_mul(cd as i32).wrapping_add(md) & M30;
    me -= m0_inv32.wrapping_mul(ce as i32).wrapping_add(me) & M30;
    cd += wide(m[0], md);
    ce += wide(m[0], me);
    debug_assert!(cd as i32 & M30 == 0 && ce as i32 & M30 == 0);
    cd >>= 30;
    ce >>= 30;

    for i in 1..L {
        let (mi, di, ei) = (m[i], d[i], e[i]);
        cd += wide(u, di) + wide(v, ei) + wide(mi, md);
        ce += wide(q, di) + wide(r, ei) + wide(mi, me);
        d[i - 1] = cd as i32 & M30;
        cd >>= 30;
        e[i - 1] = ce as i32 & M30;
        ce >>= 30;
    }
    d[L - 1] = cd as i32;
    e[L - 1] = ce as i32;
}

// (f, g) <- t繚(f, g) / 2^30, exact.
fn update_fg30<const L: usize>(f: &mut [i32; L], g: &mut [i32; L], t: &[i32; 4]) {
    let [u, v, q, r] = *t;
    let wide = |a: i32, b: i32| i64::from(a) * i64::from(b);

    let (fi, gi) = (f[0], g[0]);
    let mut cf = wide(u, fi) + wide(v, gi);
    let mut cg = wide(q, fi) + wide(r, gi);
    debug_assert!(cf as i32 & M30 == 0 && cg as i32 & M30 == 0);
    cf >>= 30;
    cg >>= 30;

    for i in 1..L {
        let (fi, gi) = (f[i], g[i]);
        cf += wide(u, fi) + wide(v, gi);
        cg += wide(q, fi) + wide(r, gi);
        f[i - 1] = cf as i32 & M30;
        cf >>= 30;
        g[i - 1] = cg as i32 & M30;
        cg >>= 30;
    }
    f[L - 1] = cf as i32;
    g[L - 1] = cg as i32;
}

// d <- -d when cond is all ones, unchanged when it is zero.
fn cnegate30<const L: usize>(cond: i32, d: &mut [i32; L]) {
    let mut c = 0i32;
    for digit in &mut d[..L - 1] {
        c += (*digit ^ cond) - cond;
        *digit = c & M30;
        c >>= 30;
    }
    c += (d[L - 1] ^ cond) - cond;
    d[L - 1] = c;
}

// d from (-2m, m) into [0, m): add m if negative, negate with f's sign, add m if negative.
fn cnormalize30<const L: usize>(cond_negate: i32, d: &mut [i32; L], m: &[i32; L]) {
    let last = L - 1;
    {
        let mut c = 0i32;
        let cond_add = d[last] >> 31;
        for i in 0..last {
            let di = d[i] + (m[i] & cond_add);
            let di = (di ^ cond_negate) - cond_negate;
            c += di;
            d[i] = c & M30;
            c >>= 30;
        }
        let di = d[last] + (m[last] & cond_add);
        let di = (di ^ cond_negate) - cond_negate;
        c += di;
        d[last] = c;
    }
    {
        let mut c = 0i32;
        let cond_add = d[last] >> 31;
        for i in 0..last {
            let di = d[i] + (m[i] & cond_add);
            c += di;
            d[i] = c & M30;
            c >>= 30;
        }
        let di = d[last] + (m[last] & cond_add);
        c += di;
        d[last] = c;
        debug_assert!(c >> 30 == 0);
    }
}

fn encode30<const N: usize, const L: usize>(bits: usize, x: &[u32; N]) -> [i32; L] {
    let mut bits = bits as isize;
    let mut z = [0; L];
    let (mut avail, mut data) = (0isize, 0u64);
    let (mut x_off, mut z_off) = (0, 0);
    while bits > 0 {
        if avail < bits.min(30) {
            data |= u64::from(x[x_off]) << avail;
            x_off += 1;
            avail += 32;
        }
        z[z_off] = data as i32 & M30;
        z_off += 1;
        data >>= 30;
        avail -= 30;
        bits -= 30;
    }
    z
}

fn decode30<const N: usize, const L: usize>(bits: usize, x: &[i32; L]) -> [u32; N] {
    let mut bits = bits as isize;
    let mut z = [0; N];
    let (mut avail, mut data) = (0isize, 0u64);
    let (mut x_off, mut z_off) = (0, 0);
    while bits > 0 {
        while avail < bits.min(32) {
            data |= (x[x_off] as u32 as u64) << avail;
            x_off += 1;
            avail += 30;
        }
        z[z_off] = data as u32;
        z_off += 1;
        data >>= 32;
        avail -= 32;
        bits -= 32;
    }
    z
}

// 1 when x is the single digit y, else 0.
fn equal_to<const L: usize>(x: &[i32; L], y: i32) -> u32 {
    let d = x[1..]
        .iter()
        .fold((x[0] ^ y) as u32, |d, &digit| d | digit as u32);
    ((d | d.wrapping_neg()) >> 31) ^ 1
}

#[cfg(test)]
mod tests {
    use super::{inverse32, mod_odd_inverse};

    #[test]
    fn small_moduli_invert_every_unit_and_refuse_zero() {
        let m = [101u32];
        for x in 1..101u32 {
            let (z, ok) = mod_odd_inverse::<1, 1>(&m, &[x]);
            assert_eq!(
                (ok, (u64::from(z[0]) * u64::from(x)) % 101),
                (1, 1),
                "x = {x}"
            );
        }
        assert_eq!(mod_odd_inverse::<1, 1>(&m, &[0]), ([0], 0));
    }

    #[test]
    fn the_word_inverse_is_exact_mod_2_32() {
        for d in [1u32, 3, 0xFFFF_FFFF, 0x1234_5679] {
            assert_eq!(d.wrapping_mul(inverse32(d)), 1);
        }
    }
}
