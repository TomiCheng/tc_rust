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
| `PaddedBigUint` | 堆積儲存，建構時決定寬度，保留前導零 | yes |

Name the fixed-width types through the bit-width aliases: `U64` `U128` `U256`
`U384` `U512` `U521` `U1024` `U1536` `U2048` `U3072` `U4096`, and `I64` `I128`
`I1024`. Limb width follows the target and is not part of the public API.

Conversions name their byte order, so callers choose it explicitly instead of
inheriting an internal layout.

## Trait implementations

`BU` is `BigUint`, `BI` is `BigInt`, `FU` is `FixedBigUint<N>` and `FI` is
`FixedBigInt<N>`. `PU` 是需要 `alloc` 的 `PaddedBigUint`。The groups follow the modules under `src/traits/`. A blank
cell marks a contract that does not apply to that representation rather than
one that is merely missing; the reasons follow.

### `numeric` — identities, markers and bound aggregators

| Trait | BU | BI | FU | FI | PU |
| --- | :-: | :-: | :-: | :-: | :-: |
| `Zero` `One` `Num` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `Bounded` | | | ✓ | ✓ |  |
| `Signed` | | ✓ | | ✓ |  |
| `Unsigned` | ✓ | | ✓ | | ✓ |
| `NumOps` `NumRef` `RefNum` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `NumAssignOps` `NumAssign` `NumAssignRef` | ✓ | ✓ | ✓ | ✓ | ✓ |

The last two rows are blanket implementations over the operator bounds rather
than per-type implementations, so every type meeting those bounds gets them.

### `ops` — big-integer operations

| Trait | BU | BI | FU | FI | PU |
| --- | :-: | :-: | :-: | :-: | :-: |
| `Pow` `Square` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `DivRem` `RemEuclid` `Gcd` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `ModInverse` `ModPow` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `ModAdd` `ModSub` `ModMul` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `BitOps` `AndNot` | ✓ | ✓ | ✓ | ✓ | ✓ |

### `checked` — overflow policies

| Trait | BU | BI | FU | FI | PU |
| --- | :-: | :-: | :-: | :-: | :-: |
| `CheckedAdd` `CheckedSub` `CheckedMul` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `CheckedDiv` `CheckedRem` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `CheckedShl` `CheckedShr` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `CheckedNeg` `WrappingNeg` | | ✓ | | ✓ |  |
| `OverflowingAdd` `WrappingAdd` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `OverflowingSub` `WrappingSub` | | ✓ | ✓ | ✓ | ✓ |
| `OverflowingMul` `WrappingMul` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `SaturatingAdd` `SaturatingSub` `SaturatingMul` | ✓ | ✓ | ✓ | ✓ | ✓ |

### `convert` — primitive conversion

| Trait | BU | BI | FU | FI | PU |
| --- | :-: | :-: | :-: | :-: | :-: |
| `FromPrimitive` `ToPrimitive` | ✓ | ✓ | ✓ | ✓ | ✓ |

### `array` — byte and word slice conversion

| Trait | BU | BI | FU | FI | PU |
| --- | :-: | :-: | :-: | :-: | :-: |
| `ArrayEncoding` | ✓ | ✓ | ✓ | ✓ | ✓ |

`ArrayEncoding` names the byte order in each method rather than exposing the
internal little-endian limb layout, so callers pick the external format
explicitly.

### `random` — randomised construction and primality

Requires the `rand_core` feature.

| Trait | BU | BI | FU | FI | PU |
| --- | :-: | :-: | :-: | :-: | :-: |
| `Random` | | | ✓ | ✓ |  |
| `RandomBits` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `RandomMod` | ✓ | | ✓ | | ✓ |
| `ProbablePrime` `IsProbablePrime` `NextProbablePrime` | ✓ | ✓ | ✓ | ✓ | ✓ |

### Why the blanks

- `Signed` and `Unsigned` partition the four types by sign, as do `CheckedNeg`
  and `WrappingNeg`: negation is only meaningful where the sign bit is.
  `PU` 比照 `FU`／`BU`：支援 `Unsigned`，不支援 `Signed`、`CheckedNeg`、`WrappingNeg`。
- `Bounded` and `Random` need a width known ahead of time, so they exist only
  for the fixed-width pair. `RandomBits` takes the bit length as an argument
  and therefore applies to all four.
  `PU` 的寬度在執行期決定，無法提供型別層的 `Bounded::MIN`／`MAX`，
  也無法從沒有寬度參數的 `Random::random_from_rng` 得知精度，所以這兩列留空；
  `RandomBits` 有位元數參數，可決定儲存寬度，因此支援。
- `RandomMod` samples below an unsigned modulus, so the signed types do not
  implement it.
- `OverflowingSub` and `WrappingSub` need a width to wrap at. `BigUint` grows
  on demand and cannot represent a negative result, so an underflowing
  subtraction has nothing to wrap to; use `CheckedSub` there instead.
  `PU` 則有實際儲存寬度，因此支援 `OverflowingSub` 與 `WrappingSub`，
  跨寬度時以兩邊最大寬度為環繞界限。

The `BU` and `BI` columns require the `alloc` feature throughout.

### `PU` 的寬度與時間契約

所有新增運算子與數值 trait 都是**變動時間：只能用於公開值**。
二元運算先補零到 `max(lhs.len(), rhs.len())`，結果與賦值目的地採該寬度；
加減乘的結果放不下會 panic，`Checked*`／`Wrapping*`／`Saturating*` 則提供明確的溢位策略。
位移運算子沿用 `FixedBigUint`：位移量超寬時 panic，`<<` 移出的高位截斷；
要拒絕移出非零高位的情況請用 `CheckedShl`。
零寬零是運算子的特例：`<<`／`>>`／`<<=`／`>>=` 對任何位移量都保留零寬，不 panic。
具名 `shl`／`shr` 則對所有寬度都是全函式：任意位移量都能產生結果，
`shl` 另回傳是否移出非零位元的旗標。
具名 CT 方法 `add`、`sub`、`mul_wide`、`ct_eq` 與選擇／原地操作仍要求同寬。
秘密值請用這些 CT 方法；秘密模冪指數請直接用 `PaddedMontyForm::pow_ct`。
若作用域內匯入 `core::ops::Add`／`Sub` 等同名 trait，方法解析可能選到運算子；
CT 路徑請明寫 `PaddedBigUint::add(&a, &b)`、`PaddedBigUint::sub(&a, &b)` 等完整呼叫。

`Zero`／`Default` 建立零寬，`One` 建立一個 limb；整數 `FromPrimitive` 依來源型別
位元數決定寬度。字串解析依數值決定最小寬度，需要特定寬度請接 `resize`。
模運算以模數寬度輸出，`Gcd`／`DivRem` 以兩邊最大寬度輸出。
`NextProbablePrime` 保留原寬度，超寬回 `None`；`ProbablePrime` 是可能質數生成，並非數學證明。

`ArrayEncoding` 的一般輸出保留完整儲存寬度，`*_unsigned*` 輸出最短 magnitude。
trait 的 caller-buffer 寫入只改動回傳長度的前綴，和 `FixedBigUint` 一致。
既有 `PaddedBigUint::write_be_bytes` 仍按傳入 buffer 長度補零；
需要 trait 版本請明寫 `ArrayEncoding::write_be_bytes(&value, out)`。

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
