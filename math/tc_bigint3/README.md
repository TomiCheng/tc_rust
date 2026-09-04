# tc_bigint3

`tc_bigint3` provides four little-endian integer representations:

- `BigUint` and `BigInt` grow using `Vec<Limb>` and require the default `alloc`
  feature.
- `FixedBigUint<N>` and `FixedBigInt<N>` contain exactly `[Limb; N]` and never
  allocate. They remain available with `default-features = false`.

The default features are `alloc` and `rand_core`. Use
`default-features = false, features = ["rand_core"]` for fixed-width random and
prime operations without an allocator, or disable both features for fixed-width
arithmetic only.

Signed values use two's complement. Limb index zero and external slice index
zero are always the least-significant unit.

The crate defines its own numeric traits in `traits.rs`; it does not depend on
`num-traits`, and the local traits are not type-compatible with
`num_traits::*`.

```rust
# #[cfg(feature = "alloc")]
# {
use tc_bigint3::{BigUint, Gcd, ModPow};

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

## Little-endian conversion

All four types accept `[u8]`, `[u32]`, and `[u64]` slices. Variable-width
types return canonical `Vec` encodings; fixed-width types write their complete
width into caller-owned buffers.

```rust
use tc_bigint3::{FixedBigInt, ToPrimitive, Word};

type I128 = FixedBigInt<{ 128 / Word::BITS as usize }>;

// A one-byte signed value is sign-extended into the fixed-width destination.
let minus_two = I128::from_le_bytes(&[0xfe]).unwrap();
assert_eq!(minus_two.to_i64(), Some(-2));

let mut words = [0_u64; 2];
assert_eq!(minus_two.write_le_u64(&mut words), Ok(2));
assert_eq!(words, [u64::MAX - 1, u64::MAX]);
```

For signed types, `from_le_*` and `write_le_*` use two's-complement data.
Explicit `from_unsigned_le_*` constructors are available when a positive
magnitude must be converted into a signed type.

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
use tc_bigint3::{
    rand_core::{self, TryRng},
    FixedBigUint, NonZero, ProbablePrime, Random, RandomBits, RandomMod, Word,
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

type U128 = FixedBigUint<{ 128 / Word::BITS as usize }>;

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
use tc_bigint3::{rand_core::TryRng, BigUint};

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
