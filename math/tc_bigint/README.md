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
| `PaddedBigInt` | 堆積儲存，建構時決定二補數寬度，保留符號擴展位 | yes |

Name the fixed-width types through the bit-width aliases: `U64` `U128` `U256`
`U384` `U512` `U521` `U1024` `U1536` `U2048` `U3072` `U4096`, and `I64` `I128`
`I1024`. Limb width follows the target and is not part of the public API.

Conversions name their byte order, so callers choose it explicitly instead of
inheriting an internal layout.

## Trait implementations

`BU` is `BigUint`, `BI` is `BigInt`, `FU` is `FixedBigUint<N>` and `FI` is
`FixedBigInt<N>`.

`PU`／`PI` 是需要 `alloc` 的 `PaddedBigUint`／`PaddedBigInt`。

The groups follow the modules under `src/traits/`. A blank
cell marks a contract that does not apply to that representation rather than
one that is merely missing; the reasons follow.

### `numeric` — identities, markers and bound aggregators

| Trait | BU | BI | FU | FI | PU | PI |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| `Zero` `One` `Num` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `Bounded` | | | ✓ | ✓ |  |  |
| `Signed` | | ✓ | | ✓ |  | ✓ |
| `Unsigned` | ✓ | | ✓ | | ✓ |  |
| `NumOps` `NumRef` `RefNum` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `NumAssignOps` `NumAssign` `NumAssignRef` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

The last two rows are blanket implementations over the operator bounds rather
than per-type implementations, so every type meeting those bounds gets them.

### `ops` — big-integer operations

| Trait | BU | BI | FU | FI | PU | PI |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| `Pow` `Square` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `DivRem` `RemEuclid` `Gcd` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `ModInverse` `ModPow` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `ModAdd` `ModSub` `ModMul` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `BitOps` `AndNot` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### `checked` — overflow policies

| Trait | BU | BI | FU | FI | PU | PI |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| `CheckedAdd` `CheckedSub` `CheckedMul` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `CheckedDiv` `CheckedRem` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `CheckedShl` `CheckedShr` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `CheckedNeg` `WrappingNeg` | | ✓ | | ✓ |  | ✓ |
| `OverflowingAdd` `WrappingAdd` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `OverflowingSub` `WrappingSub` | | ✓ | ✓ | ✓ | ✓ | ✓ |
| `OverflowingMul` `WrappingMul` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `SaturatingAdd` `SaturatingSub` `SaturatingMul` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### `convert` — primitive conversion

| Trait | BU | BI | FU | FI | PU | PI |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| `FromPrimitive` `ToPrimitive` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### `array` — byte and word slice conversion

| Trait | BU | BI | FU | FI | PU | PI |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| `ArrayEncoding` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

`ArrayEncoding` names the byte order in each method rather than exposing the
internal little-endian limb layout, so callers pick the external format
explicitly.

### `random` — randomised construction and primality

Requires the `rand_core` feature.

| Trait | BU | BI | FU | FI | PU | PI |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| `Random` | | | ✓ | ✓ |  |  |
| `RandomBits` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `RandomMod` | ✓ | | ✓ | | ✓ |  |
| `ProbablePrime` `IsProbablePrime` `NextProbablePrime` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### Why the blanks

- `Signed` and `Unsigned` partition the six types by sign, as do `CheckedNeg`
  and `WrappingNeg`: negation is only meaningful where the sign bit is.
  `PU` 比照 `FU`／`BU`：支援 `Unsigned`，不支援 `Signed`、`CheckedNeg`、`WrappingNeg`。
  `PI` 比照 `FI`／`BI`：支援 `Signed`、`CheckedNeg`、`WrappingNeg`，不支援 `Unsigned`。
- `Bounded` and `Random` need a width known ahead of time, so they exist only
  for the compile-time fixed-width pair. `RandomBits` takes the bit length as an argument
  and therefore applies to all six.
  `PU`／`PI` 的寬度在執行期決定，無法提供型別層的 `Bounded::MIN`／`MAX`，
  也無法從沒有寬度參數的 `Random::random_from_rng` 得知精度，所以這兩列留空；
  `RandomBits` 有位元數參數，可決定儲存寬度，因此支援。
- `RandomMod` samples below an unsigned modulus, so the signed types do not
  implement it.
- `OverflowingSub` and `WrappingSub` need a width to wrap at. `BigUint` grows
  on demand and cannot represent a negative result, so an underflowing
  subtraction has nothing to wrap to; use `CheckedSub` there instead.
  `PU` 則有實際儲存寬度，因此支援 `OverflowingSub` 與 `WrappingSub`，
  跨寬度時以兩邊最大寬度為環繞界限。

The `BU`, `BI`, `PU` and `PI` columns require the `alloc` feature throughout.

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

### `PI` 的寬度與時間契約

`PaddedBigInt` 使用二補數，最高位是符號位。所有運算子與數值 trait 都是
**變動時間：只能用於公開值**。二元運算以符號擴展補到最大寬度，
加減乘、除法的結果放不下時 panic；模運算採模數寬度，並委派 `BigInt`。
`ModPow` 會洩漏指數，不可用於秘密指數，也不提供有號 Montgomery 入口。

具名 CT 算術僅有嚴格同寬的 `add`／`sub`，回傳**有號溢位**，不是進位／借位。
`ct_eq` 與條件選擇同樣嚴格同寬。乘法與位移採私有固定排程核心，
仍納入 CT 回歸掃描；沒有公有 `mul_wide`、具名 `shl`／`shr` 或原地 CT 算術系列。
`Zeroize` 與 `set_zero()` 清除全部 limb 並保留寬度；`Zero::zero()`／`Default`
則建立零寬。`One` 建立一個 limb，離開作用域時透過 `ZeroizeOnDrop` 清除儲存。

擴寬補符號位；縮窄要求被移除的 limb 都是原符號擴展值，且保留部分的符號位
不變。零寬只表示非負零。`>>` 是算術右移，負值高位補一；`<<` 截斷高位，
只檢查位移量。`CheckedShl` 另要求「左移後算術右移還原」得到原值，
才能保證有號數值沒有溢位。零寬的位移運算子對任何位移量都回零寬零。

有號 `FromPrimitive` 依來源型別位元數決定寬度；無號輸入若放不進同樣寬度的
有號範圍則回 `None`。字串解析採 `BigInt` 的最小二補數寬度。
`ArrayEncoding` 一般輸入採二補數、輸出保留完整寬度；無號輸入採非負 magnitude，
輸出採絕對值的最短 magnitude。無號輸入若需要額外符號 limb 則回 `InputTooLarge`。
PU ↔ PI 的 `TryFrom` 保持同寬：PI 負值轉 PU 回 `NegativeValue`，
PU 最高位為一時轉 PI 回 `InputTooLarge`；可先明確加寬 PU 再轉換。

`RandomBits::random_bits(bits)` 的值域保持 `0..2^bits`，寬度為
`limbs_for_bits(bits + 1)`，預留符號位；bits 為零時亦有一個 limb。
明確 precision 的版本採 `limbs_for_bits(precision)`，但必須滿足
`precision > bits`，否則回 `BitLengthTooLarge`；無號版本允許相等，
兩者差別就是符號位。`ProbablePrime` 同樣預留符號位；`NextProbablePrime`
保留原寬度，超寬回 `None`。質數測試的通過不代表數學證明。

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
six types and return the least non-negative residue.

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

`PaddedMontyParams`／`PaddedMontyForm` 是需要 `alloc`、寬度在執行期決定的
第三對，供固定寬度的秘密值使用。參數以 `Arc` 共享；clone 參數只遞增參考計數，
不複製模數與 radix 常數。form 的 clone 仍會複製自身的值。
參數由 form 持有且不帶借用生命週期，因此 form 可以直接存進結構。

秘密輸入選 `PaddedMontyForm::new_ct`，以固定排程、不經除法進域；公開輸入
選 `new`，以變動時間的除法約簡進域。與逐位元約簡相比，公開值的除法路徑
可快兩個數量級；目前 `new_ct` 對不超過模數兩倍寬的輸入已改走三次模乘，
該倍率不代表兩個入口在所有寬度上的效能差距。
秘密指數選 `pow_ct`，它處理完整儲存寬度的每個位元，包含前導零；
公開指數選滑動視窗的 `pow`。既有動態 Montgomery 後端供公開值使用，
`FixedMontyForm<N>` 則適用於編譯期已知寬度的 CT 路徑。

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
