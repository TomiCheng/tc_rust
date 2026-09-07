# tc_bigint

`tc_bigint` provides four little-endian integer representations:

- `BigUint` and `BigInt` grow using `Vec<Limb>` and require the default `alloc`
  feature.
- `FixedBigUint<N>` and `FixedBigInt<N>` store their `N` limbs in `tc_limb::LimbArray<N>`; their
  arithmetic and caller-buffer encodings never allocate. They remain available
  with `default-features = false`. The optional `to_str_radix` convenience
  method returns a `String` and therefore requires `alloc`.

The default features are `alloc` and `rand_core`. Use
`default-features = false, features = ["rand_core"]` for fixed-width random and
prime operations without an allocator, or disable both features for fixed-width
arithmetic only.

Signed values use two's complement. Limb index zero is always the
least-significant limb. External slices explicitly select little-endian or
big-endian order through their method names.

Limb width is a target detail and is not part of this crate's public API. Size
fixed-width values with the bit-width aliases (`U256`, `U2048`, ...) or with
`limbs_for_bits(bits)` where a limb count is needed as a const generic
argument. `tc_limb::{Limb, Word, WideWord}` remain available from that crate
for callers working at the limb level. `LimbArray` provides
only unsigned fixed-width primitives, with no sign interpretation for the
highest bit. Two's-complement sign checks and absolute values belong to
`FixedBigInt`. Variable-length arithmetic and allocation remain in `tc_bigint`.

The crate defines its own numeric traits in `traits.rs`; it does not depend on
`num-traits`, and the local traits are not type-compatible with
`num_traits::*`.

## Trait implementations

`BU` is `BigUint`, `BI` is `BigInt`, `FU` is `FixedBigUint<N>` and `FI` is
`FixedBigInt<N>`. The groups follow the modules under `src/traits/`. A blank
cell marks a contract that does not apply to that representation rather than
one that is merely missing; the reasons follow.

### `numeric` — identities, markers and bound aggregators

| Trait | BU | BI | FU | FI |
| --- | :-: | :-: | :-: | :-: |
| `Zero` `One` `Num` | ✓ | ✓ | ✓ | ✓ |
| `Bounded` | | | ✓ | ✓ |
| `Signed` | | ✓ | | ✓ |
| `Unsigned` | ✓ | | ✓ | |
| `NumOps` `NumRef` `RefNum` | ✓ | ✓ | ✓ | ✓ |
| `NumAssignOps` `NumAssign` `NumAssignRef` | ✓ | ✓ | ✓ | ✓ |

The last two rows are blanket implementations over the operator bounds rather
than per-type implementations, so every type meeting those bounds gets them.

### `ops` — big-integer operations

| Trait | BU | BI | FU | FI |
| --- | :-: | :-: | :-: | :-: |
| `Pow` `Square` | ✓ | ✓ | ✓ | ✓ |
| `DivRem` `RemEuclid` `Gcd` | ✓ | ✓ | ✓ | ✓ |
| `ModInverse` `ModPow` | ✓ | ✓ | ✓ | ✓ |
| `ModAdd` `ModSub` `ModMul` | ✓ | ✓ | ✓ | ✓ |
| `BitOps` `AndNot` | ✓ | ✓ | ✓ | ✓ |

### `checked` — overflow policies

| Trait | BU | BI | FU | FI |
| --- | :-: | :-: | :-: | :-: |
| `CheckedAdd` `CheckedSub` `CheckedMul` | ✓ | ✓ | ✓ | ✓ |
| `CheckedDiv` `CheckedRem` | ✓ | ✓ | ✓ | ✓ |
| `CheckedShl` `CheckedShr` | ✓ | ✓ | ✓ | ✓ |
| `CheckedNeg` `WrappingNeg` | | ✓ | | ✓ |
| `OverflowingAdd` `WrappingAdd` | ✓ | ✓ | ✓ | ✓ |
| `OverflowingSub` `WrappingSub` | | ✓ | ✓ | ✓ |
| `OverflowingMul` `WrappingMul` | ✓ | ✓ | ✓ | ✓ |
| `SaturatingAdd` `SaturatingSub` `SaturatingMul` | ✓ | ✓ | ✓ | ✓ |

### `convert` — primitive conversion

| Trait | BU | BI | FU | FI |
| --- | :-: | :-: | :-: | :-: |
| `FromPrimitive` `ToPrimitive` | ✓ | ✓ | ✓ | ✓ |

### `array` — byte and word slice conversion

| Trait | BU | BI | FU | FI |
| --- | :-: | :-: | :-: | :-: |
| `ArrayEncoding` | ✓ | ✓ | ✓ | ✓ |

`ArrayEncoding` names the byte order in each method rather than exposing the
internal little-endian limb layout, so callers pick the external format
explicitly.

### `random` — randomised construction and primality

Requires the `rand_core` feature.

| Trait | BU | BI | FU | FI |
| --- | :-: | :-: | :-: | :-: |
| `Random` | | | ✓ | ✓ |
| `RandomBits` | ✓ | ✓ | ✓ | ✓ |
| `RandomMod` | ✓ | | ✓ | |
| `ProbablePrime` `IsProbablePrime` `NextProbablePrime` | ✓ | ✓ | ✓ | ✓ |

### Why the blanks

- `Signed` and `Unsigned` partition the four types by sign, as do `CheckedNeg`
  and `WrappingNeg`: negation is only meaningful where the sign bit is.
- `Bounded` and `Random` need a width known ahead of time, so they exist only
  for the fixed-width pair. `RandomBits` takes the bit length as an argument
  and therefore applies to all four.
- `RandomMod` samples below an unsigned modulus, so the signed types do not
  implement it.
- `OverflowingSub` and `WrappingSub` need a width to wrap at. `BigUint` grows
  on demand and cannot represent a negative result, so an underflowing
  subtraction has nothing to wrap to; use `CheckedSub` there instead.

The `BU` and `BI` columns require the `alloc` feature throughout.

```rust
# #[cfg(feature = "alloc")]
# {
use tc_bigint::{BigUint, Gcd, ModPow};

fn gcd<T>(left: &T, right: &T) -> T
where
    T: Gcd<Output = T>,
{
    left.gcd(right)
}

fn mod_pow<T>(base: &T, exponent: &T, modulus: &T) -> T
where
    T: ModPow<Output = T>,
{
    base.mod_pow(exponent, modulus)
}

let three = BigUint::from(3_u8);
let seven = BigUint::from(7_u8);
assert_eq!(gcd(&BigUint::from(48_u8), &BigUint::from(18_u8)), BigUint::from(6_u8));
assert_eq!(mod_pow(&three, &BigUint::from(4_u8), &seven), BigUint::from(4_u8));
# }
```

## Array conversion

All four types accept little-endian and big-endian `[u8]`, `[u32]`, and `[u64]`
slices. Variable-width signed encodings are canonical two's complement.
Fixed-width signed writers retain the complete fixed width, while the
`write_unsigned_*` family emits the shortest absolute magnitude. Every writer
has a matching `*_length()` query, so caller-owned storage can be sized without
first allocating a temporary `Vec`.

```rust
use tc_bigint::{I128, ToPrimitive};


// A one-byte signed value is sign-extended into the fixed-width destination.
let minus_two = I128::from_le_bytes(&[0xfe]).unwrap();
assert_eq!(minus_two.to_i64(), Some(-2));

let mut words = [0_u64; 2];
assert_eq!(minus_two.write_le_u64(&mut words), Ok(2));
assert_eq!(words, [u64::MAX - 1, u64::MAX]);
```

For signed types, `from_le_*` and `write_le_*` use two's-complement data.
The corresponding `from_be_*` and `write_be_*` methods use big-endian order.
Explicit `from_unsigned_*` constructors and `to_unsigned_*` or
`write_unsigned_*` encoders operate on a positive absolute magnitude instead
of a signed representation.

```rust
# #[cfg(feature = "alloc")]
# {
use tc_bigint::BigInt;

let value = BigInt::from(-129_i16);
assert_eq!(value.to_be_bytes(), [0xff, 0x7f]);
assert_eq!(value.to_unsigned_be_bytes(), [0x81]);

let mut modulus = [0_u8; 1];
assert_eq!(modulus.len(), value.byte_length_unsigned());
assert_eq!(value.write_unsigned_be_bytes(&mut modulus), Ok(1));
# }
```

## Checked arithmetic, formatting, and conversions

Fixed-width arithmetic follows primitive-integer conventions. The ordinary
operators panic on overflow in every build profile. The `Checked*`,
`Overflowing*`, `Wrapping*`, and `Saturating*` traits make the desired behavior
explicit. Division and remainder return `None` for a zero divisor; signed
fixed-width division also rejects `MIN / -1`.

Only fixed-width integers implement `Bounded`; dynamically growing integers
have no finite minimum or maximum. Dynamic `CheckedDiv` and `CheckedRem` still
return `None` for division by zero. Their other checked, overflowing, wrapping,
and saturating operations return the exact unbounded result and never report
overflow. Unsigned integers intentionally do not implement the negation
families, and `BigUint` does not expose wrapping or overflowing subtraction
because either operation would require an implicit fixed width.

`FixedBigUint::mul_wide` and `square_wide` return the full double-width result
as `(low, high)` halves. A tuple is used because stable Rust cannot yet express
`[Limb; N * 2]` for arbitrary const-generic `N`. The two halves are fixed-size
and allocation-free.

All four integer types implement decimal `FromStr`, `Display`, numeric `Debug`,
`Binary`, `Octal`, `LowerHex`, and `UpperHex`. Fixed-width formatting itself is
allocation-free. Signed formatting uses a leading minus sign and magnitude,
including for hexadecimal output.

```rust
use tc_bigint::{
    Bounded, CheckedMul, ConversionError, FixedBigInt, FixedBigUint,
    OverflowingMul, U128, I128,
};


let value: U128 = "255".parse().unwrap();
assert_eq!(format!("{value:#06x}"), "0x00ff");
assert_eq!(format!("{:?}", I128::from(-42_i8)), "-42");

let max = U128::MAX;
assert_eq!(CheckedMul::checked_mul(&max, &U128::from(2_u8)), None);
assert!(OverflowingMul::overflowing_mul(&max, &U128::from(2_u8)).1);
let (_low, high) = max.mul_wide(&U128::from(2_u8));
assert_eq!(high, U128::from(1_u8));
assert_eq!(<U128 as Bounded>::MIN, U128::zero());

let signed = I128::from(-1_i8);
assert_eq!(
    U128::try_from(signed),
    Err(ConversionError::NegativeValue),
);
let wider = FixedBigUint::<4>::try_from(&value).unwrap();
assert_eq!(wider, FixedBigUint::from(255_u16));
```

Conversions between const-generic fixed widths use `TryFrom` for both widening
and narrowing. Rust cannot provide a blanket widening-only `From` implementation
on stable Rust: the compiler cannot express `DESTINATION >= SOURCE`, and a
generic `From<FixedBigUint<SOURCE>> for FixedBigUint<DESTINATION>` would overlap
with the standard library's `From<T> for T`. Widening therefore succeeds through
the same checked API that reports truncation when narrowing.

`leading_zeros` is defined only for fixed-width integers. A canonical dynamic
integer has no stored leading zero limbs, so its number of leading zeros is not
defined without supplying an external width.

## Random values and probable primes

The random and prime APIs accept the caller's `rand_core::Rng`; the crate never
selects a global RNG. `Rng` describes an infallible random source but does not
promise cryptographic security. Secret primes and secret random integers must
use a generator which also satisfies `rand_core::CryptoRng` and has been seeded
securely.

Following `crypto-bigint`, `Random` and `RandomBits` use a fallible `TryRng`
required method and provide an infallible `Rng` convenience method.
`RandomMod` uses rejection sampling and is explicitly named
`random_mod_vartime`. `ProbablePrime`, `IsProbablePrime`, and
`NextProbablePrime` add the prime operations required by this crate. Fixed-width
generation performs no allocation. Its `next_probable_prime` returns `None`
when the next prime does not fit.

Only the fixed-width types implement `Random`, because they have an intrinsic
full width. The canonical `BigUint` and `BigInt` representations do not retain a
requested storage precision, so callers must use `RandomBits` for them.

These implementations are currently variable-time. In particular, primality
testing, modular exponentiation, division, and rejection sampling must not be
treated as side-channel-hardened merely because their contracts resemble
`crypto-bigint`.

Multi-limb division uses normalized Knuth division. Modular exponentiation uses
sliding windows and Montgomery multiplication for odd moduli; even moduli use a
division-reduction fallback. Both the allocating and fixed-width paths use
these implementations, while the fixed-width path remains allocation-free.

Integer square root is intentionally not part of the current contract. Bouncy
Castle's `BigInteger` does not expose it, and no migrated algorithm currently
requires it. It can be introduced as a separate operation family when an
algorithm such as integer factorization has a concrete need for it.

## Modular arithmetic

`ModAdd`, `ModSub`, and `ModMul` are implemented by all four integer types.
They return the least non-negative residue and avoid constructing an
overflowing full-width product. In particular, `FixedBigUint<N>::mod_mul`
works when the ordinary fixed-width `Mul` operation would overflow.

Odd moduli can also be prepared once. `MontyParams<BigUint>` and
`FixedMontyParams<N>` store the Montgomery inverse, `R mod n`, and `R² mod n`.
`MontyForm<BigUint>` and `FixedMontyForm<N>` then reuse those constants for
addition, subtraction, multiplication, squaring, and exponentiation. Both
forms implement `Retrieve`, and also provide an inherent `retrieve` method.
The fixed-width forms remain allocation-free. Even moduli continue to use the
division-reduction fallback exposed through the ordinary `Mod*` traits.

```rust
use tc_bigint::{
    modular::{FixedMontyForm, FixedMontyParams},
    ModAdd, ModMul, ModSub, Odd, U128,
};

let modulus = U128::from(101_u8);
let maximum = U128::MAX;

// The ordinary fixed-width product overflows, but modular multiplication does
// not need that product to fit in U128.
assert_eq!(maximum.mod_mul(&maximum, &modulus), U128::from(80_u8));
assert_eq!(U128::from(100_u8).mod_add(&U128::from(5_u8), &modulus), U128::from(4_u8));
assert_eq!(U128::from(3_u8).mod_sub(&U128::from(5_u8), &modulus), U128::from(99_u8));

let params = FixedMontyParams::new(Odd::new(modulus).unwrap());
let seven = FixedMontyForm::new(&U128::from(7_u8), params);
let nine = FixedMontyForm::new(&U128::from(9_u8), params);
assert_eq!((seven * nine).retrieve(), U128::from(63_u8));
assert_eq!(seven.pow(&U128::from(20_u8)).retrieve(), U128::from(84_u8));
```

`Odd<T>` only records the checked parity invariant; it does not claim that the
value is prime. All modular arithmetic, including Montgomery operations,
remains variable-time.

For an arbitrary value, Miller-Rabin runs `ceil(certainty / 2)` rounds, based
on the standard upper bound of one false-positive chance in four per round.
During probable-prime generation, candidates are uniformly random, so the
100-bit default follows Bouncy Castle's size-aware policy: 16 rounds from 256
bits, 8 rounds from 512 bits, and 4 rounds from 1024 bits. Calling
`is_probable_prime` directly does not use this reduced random-candidate policy.

```rust
# #[cfg(feature = "rand_core")]
# {
use core::convert::Infallible;
use tc_bigint::{
    rand_core::{self, TryRng},
    NonZero, ProbablePrime, Random, RandomBits, RandomMod, U128,
};

// Deterministic for a reproducible doctest. Production cryptographic code
// should supply a securely seeded CryptoRng instead.
struct DemoRng(u64);

impl TryRng for DemoRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        Ok(self.0)
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in output.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}


fn random<T: RandomBits>(bits: u32, rng: &mut impl rand_core::Rng) -> T {
    T::random_bits(rng, bits)
}

fn prime<T: ProbablePrime>(bits: u32, rng: &mut impl rand_core::Rng) -> T {
    T::probable_prime(rng, bits)
}

let mut rng = DemoRng(1);
let _full_width = U128::random_from_rng(&mut rng);
let value = random::<U128>(80, &mut rng);
assert!(value.bit_length() <= 80);

let modulus = NonZero::new(U128::from(101_u8)).unwrap();
let reduced = U128::random_mod_vartime(&mut rng, &modulus);
assert!(reduced < *modulus);

let value = prime::<U128>(16, &mut rng);
assert_eq!(value.bit_length(), 16);
assert!(value.is_probable_prime(40, &mut rng));
assert_eq!(
    U128::from(7_u8).next_probable_prime(&mut rng),
    Some(U128::from(11_u8)),
);
# }
```

The allocating types use the same API and can grow when searching for the next
prime:

```rust
# #[cfg(all(feature = "alloc", feature = "rand_core"))]
# {
use core::convert::Infallible;
use tc_bigint::{rand_core::TryRng, BigUint};

struct DemoRng(u64);

impl TryRng for DemoRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self.0.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        Ok(self.0)
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in output.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

let mut rng = DemoRng(7);
let prime = BigUint::probable_prime(&mut rng, 32);
assert_eq!(prime.bits(), 32);
assert!(prime.is_probable_prime(40, &mut rng));
assert_eq!(
    BigUint::from(7_u8).next_probable_prime(&mut rng),
    BigUint::from(11_u8),
);
# }
```

## Benchmarks

The `integer_types` benchmark compares the same positive operands across
`BigUint`, `BigInt`, `FixedBigUint`, and `FixedBigInt`. It covers 1024-bit
addition, 512-by-512-bit multiplication, 1024-by-512-bit division, and modular
exponentiation with a 1024-bit modulus:

```text
cargo bench -p tc_bigint --bench integer_types
```
