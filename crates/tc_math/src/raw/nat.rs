//! Fixed-length unsigned multi-precision integers on `[Limb; N]` — the
//! foundation for custom (per-size optimized) prime-field elliptic curves.
//!
//! Ported in spirit from Bouncy Castle's `Math.Raw.Nat` family, but the C#
//! design's two sources of duplication collapse here:
//!
//! - **len / offset / array-vs-span overloads** → Rust slices carry their length.
//! - **hand-unrolled per-size files** (`Nat128`, `Nat256`, …) → one const-generic
//!   [`Nat<N>`]; the compiler monomorphizes and LLVM unrolls per size.
//!
//! The **limb type is chosen by the target platform, never by the user**: 64-bit
//! targets use `u64` limbs (with a `u128` carry accumulator), 32-bit use `u32`
//! (with `u64`), 16-bit use `u16` (with `u32`). This is a compile-time `cfg`,
//! transparent to callers.

// target_pointer_width 只會是 "16"/"32"/"64"，三個 arm 即完整覆蓋，各給原生字寬。
#[cfg(target_pointer_width = "64")]
mod width {
    pub type Limb = u64;
    pub type Wide = u128;
    pub const BITS: usize = 64;
}
#[cfg(target_pointer_width = "32")]
mod width {
    pub type Limb = u32;
    pub type Wide = u64;
    pub const BITS: usize = 32;
}
#[cfg(target_pointer_width = "16")]
mod width {
    pub type Limb = u16;
    pub type Wide = u32;
    pub const BITS: usize = 16;
}
#[cfg(not(any(
    target_pointer_width = "16",
    target_pointer_width = "32",
    target_pointer_width = "64"
)))]
compile_error!("unsupported target_pointer_width (expected 16, 32, or 64)");

/// The platform's limb type: `u64` on 64-bit targets, `u32` on 32-bit.
pub type Limb = width::Limb;
/// Double-width accumulator for carries (`u128` / `u64`). Internal.
type Wide = width::Wide;
/// Bit width of one [`Limb`] (`64` / `32`).
pub const LIMB_BITS: usize = width::BITS;

/// Number of [`Limb`]s needed to hold `bits` bits (`⌈bits / LIMB_BITS⌉`),
/// adjusting automatically to the platform's limb width.
///
/// A `const fn` so it can size a [`Nat`] at a type alias:
/// `type P256 = Nat<{ nat_limbs(256) }>;`.
pub const fn nat_limbs(bits: usize) -> usize {
    bits.div_ceil(LIMB_BITS)
}

/// A fixed-length unsigned integer of `N` limbs (little-endian: `limbs[0]` is
/// least significant). `N` is a **limb count**; derive it from a bit width with
/// [`nat_limbs`] at a type alias rather than hard-coding it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Nat<const N: usize> {
    limbs: [Limb; N],
}

impl<const N: usize> Nat<N> {
    /// The zero value.
    pub fn zero() -> Self {
        Nat { limbs: [0; N] }
    }

    /// Wraps a limb array (little-endian word order).
    pub fn from_limbs(limbs: [Limb; N]) -> Self {
        Nat { limbs }
    }

    /// The backing limbs (little-endian word order).
    pub fn limbs(&self) -> &[Limb; N] {
        &self.limbs
    }

    /// Computes `z = x + y`, returning the carry-out (`0` or `1`). The result is
    /// written into the caller-provided `z` (buffer-reuse / carry-chaining style),
    /// corresponding to Bouncy Castle's `Nat.Add(len, x, y, z)`.
    pub fn add(x: &Self, y: &Self, z: &mut Self) -> Limb {
        let mut c: Wide = 0; // 進位累加器（比 limb 寬一倍）
        for i in 0..N {
            c += x.limbs[i] as Wide + y.limbs[i] as Wide;
            z.limbs[i] = c as Limb; // 低位落地
            c >>= LIMB_BITS; // 高位 → 下一輪進位
        }
        c as Limb // 最高 limb 的進位（0/1）
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_limbs_rounds_up_by_platform() {
        assert_eq!(nat_limbs(0), 0);
        assert_eq!(nat_limbs(1), 1);
        assert_eq!(nat_limbs(LIMB_BITS), 1);
        assert_eq!(nat_limbs(LIMB_BITS + 1), 2);
        assert_eq!(nat_limbs(256), 256 / LIMB_BITS); // 256 是 32、64 的倍數
    }

    #[test]
    fn add_no_carry() {
        let x = Nat::<4>::from_limbs([1, 2, 3, 4]);
        let y = Nat::<4>::from_limbs([10, 20, 30, 40]);
        let mut z = Nat::<4>::zero();
        assert_eq!(Nat::<4>::add(&x, &y, &mut z), 0);
        assert_eq!(z.limbs(), &[11, 22, 33, 44]);
    }

    #[test]
    fn add_carry_propagates_across_limbs() {
        // [MAX, MAX, 0] + [1, 0, 0] → 進位鏈到第 3 limb
        let x = Nat::<3>::from_limbs([Limb::MAX, Limb::MAX, 0]);
        let y = Nat::<3>::from_limbs([1, 0, 0]);
        let mut z = Nat::<3>::zero();
        assert_eq!(Nat::<3>::add(&x, &y, &mut z), 0);
        assert_eq!(z.limbs(), &[0, 0, 1]);
    }

    #[test]
    fn add_carry_out() {
        // 全 1 + 1 → 結果全 0，carry out = 1
        let x = Nat::<2>::from_limbs([Limb::MAX, Limb::MAX]);
        let y = Nat::<2>::from_limbs([1, 0]);
        let mut z = Nat::<2>::zero();
        assert_eq!(Nat::<2>::add(&x, &y, &mut z), 1);
        assert_eq!(z.limbs(), &[0, 0]);
    }

    #[test]
    fn add_matches_u128_reference() {
        // Nat<{nat_limbs(128)}> 剛好是 128-bit（u32→4、u64→2 limbs），對照原生 u128。
        const N: usize = nat_limbs(128);
        let to_nat = |mut v: u128| {
            let mut limbs: [Limb; N] = [0; N];
            for l in limbs.iter_mut() {
                *l = v as Limb;
                v >>= LIMB_BITS;
            }
            Nat::<N>::from_limbs(limbs)
        };
        let from_nat = |n: &Nat<N>| {
            let mut v: u128 = 0;
            for i in (0..N).rev() {
                v = (v << LIMB_BITS) | n.limbs()[i] as u128;
            }
            v
        };

        let a: u128 = 0x1111_2222_3333_4444_5555_6666_7777_8888;
        let b: u128 = 0xFFFF_FFFF_0000_0001_DEAD_BEEF_CAFE_BABE;
        let mut z = Nat::<N>::zero();
        let carry = Nat::<N>::add(&to_nat(a), &to_nat(b), &mut z);

        assert_eq!(from_nat(&z), a.wrapping_add(b));
        assert_eq!(carry as u128, u128::from(a.checked_add(b).is_none()));
    }
}
