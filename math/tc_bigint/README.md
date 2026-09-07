# tc_bigint

Arbitrary-precision and fixed-precision integer arithmetic, together with the
modular and primality operations that public-key cryptography needs. The crate
is `no_std`; the allocating types sit behind a feature.

The numeric traits are defined here rather than taken from `num-traits`, and
are not type-compatible with `num_traits::*`.

## Main types

| Type | Storage | Needs `alloc` |
| --- | --- | :-: |
| `BigUint` | grows as needed | yes |
| `BigInt` | grows as needed, two's complement | yes |
| `FixedBigUint<N>` | exactly `N` limbs, never allocates | |
| `FixedBigInt<N>` | exactly `N` limbs, two's complement | |

Name the fixed-width types through the bit-width aliases: `U64` `U128` `U256`
`U384` `U512` `U521` `U1024` `U1536` `U2048` `U3072` `U4096`, and `I64` `I128`
`I1024`. Limb width follows the target and is not part of the public API.

Conversions name their byte order, so callers choose it explicitly instead of
inheriting an internal layout.

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

## Wrapper types

`Odd<T>` and `NonZero<T>` carry a checked invariant in the type. Both are built
with `new`, which returns `None` when the value fails the test, and unwrapped
with `into_inner`.

They let an operation state its requirement in the signature instead of
asserting at run time: `MontyParams::new` takes an `Odd`, because Montgomery
reduction is defined only for odd moduli, and `RandomMod` takes a `NonZero`
modulus.

## Modular arithmetic

`ModAdd`, `ModSub`, `ModMul`, `ModPow` and `ModInverse` are implemented by all
four types and return the least non-negative residue.

For a modulus reused many times, prepare it once. `MontyParams<BigUint>` and
`FixedMontyParams<N>` store the Montgomery inverse, `R mod n` and `R^2 mod n`;
`MontyForm<BigUint>` and `FixedMontyForm<N>` then reuse those constants for
addition, subtraction, multiplication, squaring and exponentiation. The `Monty`
and `MontyInteger` traits abstract over both, which is how a caller stays
generic over the integer backend.

`FixedMontyForm<N>` additionally offers fixed-schedule entry points for secret
values: `new_ct` reduces without division, and `pow_ct` exponentiates without
branching on the exponent. The dynamic form has no such path, because `BigUint`
normalizes and its limb count therefore depends on the value it holds.

`mod_odd_inverse` and `mod_odd_inverse_var` implement safegcd inversion, the
first with a fixed schedule.

## Primes and randomness

With the `rand_core` feature, `Random` and `RandomBits` construct values from a
caller-supplied generator, and `RandomMod` samples below a `NonZero` modulus.

`ProbablePrime`, `IsProbablePrime` and `NextProbablePrime` cover generation and
testing. Testing combines trial division by small primes with Miller-Rabin
rounds, and the round count follows the requested certainty and the value's bit
length.

Generators are always passed in; the crate never reaches for a global one.

## Features

`alloc` and `rand_core` are on by default. Use
`default-features = false, features = ["rand_core"]` for fixed-width random and
prime operations without an allocator, or disable both for fixed-width
arithmetic only.

## Benchmarks

The `integer_types` benchmark compares the same positive operands across all
four types. It covers 1024-bit addition, 512-by-512-bit multiplication,
1024-by-512-bit division, and modular exponentiation with a 1024-bit modulus:

```text
cargo bench -p tc_bigint --bench integer_types
```
