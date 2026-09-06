# tc_limb

固定寬度、小端序 limb 算術。此 crate 使用 `#![no_std]`，不使用 `alloc`、堆積配置或 `unsafe`。正式依賴只有 `tc_constant_time`；`num-bigint` 僅用於測試 oracle，沒有 `tc_bigint` 的正式或開發依賴。

這是獨立建立的新 crate。現有 `tc_bigint` 的程式、型別與依賴都不變，尚未改用 `tc_limb`。

## 儲存模型

`Limb` 包裝一個私有的 `Word`，使用 `Limb::new(word)` 建立，以 `to_word()` 取值。

| 目標指標寬度 | `Word` | `WideWord` |
| --- | --- | --- |
| 64-bit | `u64` | `u128` |
| 16-bit、32-bit | `u32` | `u64` |

字寬沿用目前 `tc_bigint` 的 cfg，因此在 i686 上一個 limb 是 32 位元。`N` 是 limb 數量，不是位元數；固定寬度為 `N * Word::BITS`。跨平台的序列化格式應由呼叫端明確定義，不能直接假設記憶體配置與字寬一致。

`LimbArray<const N: usize>` 是無號固定寬度儲存與算術原語，最高位元不是符號位。`abs` 與 `is_negative` 等有號解讀由上層 `FixedBigInt` 負責。私有欄位為 `[Limb; N]`，索引零是最低有效字。使用 `new`、`zero`、`as_limbs`、`as_mut_limbs`、`into_limbs` 建立或取出固定長度儲存。兩個不同 `N` 的值無法互相算術運算，也不會隱式補零或截斷。

```rust
use tc_limb::{Limb, LimbArray, Word};

let max = LimbArray::new([Limb::new(Word::MAX); 2]);
let one = LimbArray::new([Limb::new(1), Limb::new(0)]);
let (sum, carry) = max.add(&one);
assert!(sum.is_zero());
assert!(carry);

let (low, high) = max.mul_wide(&one);
assert_eq!(low, max);
assert!(high.is_zero());
```

## 單一 limb 的語意

| 操作 | 結果與限制 |
| --- | --- |
| `carrying_add` | `self + rhs + carry` 的低字與進位字；輸入 carry 可為任意字，輸出 carry 可大於一 |
| `borrowing_sub` | `self - rhs - borrow` 的低字與借位位元；輸入 borrow 必須為零或一 |
| `overflowing_add`、`overflowing_sub` | 截斷結果與溢位／借位旗標 |
| `wrapping_add`、`wrapping_sub`、`wrapping_neg` | 模 `2^Word::BITS` 的結果 |
| `widening_mul` | 完整乘積的低字、高字 |
| `+`、`+=`、`-`、`-=`、`*` | 算術溢位時一律 panic，debug 與 release 相同 |
| `&`、`\|`、`^`、`!` | 對完整字執行位元運算 |
| `<< usize`、`>> usize` | 邏輯位移；位移量必須小於 `Word::BITS`，左移移出的位元直接捨棄 |

## 固定寬度方法

所有二元參數以及雙寬度運算的每一半都是相同的 `LimbArray<N>`。

| 方法 | 語意 |
| --- | --- |
| `cmp`、`Ord`、`PartialOrd` | 從最高 limb 開始，依無號數值排序 |
| `add`、`sub` | 模固定寬度的結果與最終進位／借位旗標 |
| `mul` | 乘積低半部與高半部是否非零 |
| `mul_wide`、`square_wide` | 完整乘積／平方的 `(low, high)` |
| `mul_add_to` | 將乘積加到可變的低半部與高半部累加器，回傳超出雙寬度的溢位旗標 |
| `div_rem` | 無號商與餘數；除數為零時 panic |
| `wide_rem` | `self` 為低半部、`high` 為高半部；對 `modulus` 取餘數，模數為零時 panic |
| `wrapping_neg` | 模 `2^(N * Word::BITS)` 的加法反元素，不賦予資料符號 |
| `gcd` | 無號最大公因數，`gcd(0, 0) = 0` |
| `bit_len` | 有效位元數，零為零 |
| `test_bit` | 讀取指定有效索引；超出固定寬度時 panic |
| `is_zero`、`is_one` | 是否等於零／一 |
| `shr_one` | 原地邏輯右移一位，捨棄最低位元 |
| `shl_one` | 原地左移一位，回傳被移出的最高位元 |

雙寬度結果表示 `low + high * 2^(N * Word::BITS)`。兩半各使用 `[Limb; N]`，不需要尚無法普遍使用的 `[Limb; 2 * N]` 型別運算，也不配置暫存向量。

`N = 0` 是合法的零寬度數值：所有一般算術結果為零，進位／借位／乘法溢位為假；`is_zero` 為真，`is_one` 為假。`div_rem`、`wide_rem` 必然遇到零除數而 panic；`test_bit` 沒有任何合法索引。

## 常數時間範圍

`Limb` 與 `LimbArray<N>` 實作並重新匯出 `tc_constant_time` 的 `ConditionallySelectable` 與 `ConstantTimeEq`。選取不依選擇位元或輸入值分支，相等比較讀取全部 limb 而不提早退出。這些保證針對值；公開的陣列長度 `N` 可以影響執行時間。

```rust
use tc_limb::{Choice, ConditionallySelectable, ConstantTimeEq, Limb, LimbArray};

let a = LimbArray::new([Limb::new(3)]);
let b = LimbArray::new([Limb::new(9)]);
let selected = LimbArray::conditional_select(&a, &b, Choice::from_lsb(1));
assert_eq!(selected.ct_eq(&b).unwrap_u8(), 1);
```

一般 `==`、`cmp`、零值判斷、算術與除法不宣稱常數時間。特別是除法正規化、商估計修正與 GCD 迴圈都可能依資料改變。`Choice::unwrap_u8` 會揭露比較結果；實際部署仍需依目標編譯器與硬體檢視產生的機器碼。

## 來源與維護

目前來源 `tc_bigint/src/arithmetic.rs` 實際含 25 個 `fixed_*`：19 個運算入口與 6 個內部輔助函式。排除留給上層的 `abs` 與 `is_negative` 後，其餘 17 個運算透過上述型別方法提供（比較採 `Ord::cmp`），複製的核心作為私有關聯函式置於 `src/limb_array/arithmetic.rs`，所有陣列參數均保留相同 `N`。

未複製變長算術、配置功能、解析與 `FixedBigUint` 的 CT impl。`Limb` 的六個既有 const 原語保留語意，補上私有欄位存取與缺少的運算子；新 crate 中的 CT impl 僅屬於自己的 `Limb` 與 `LimbArray`。

## 驗證

測試使用固定種子的偽隨機輸入以便重現，逐 limb 對照獨立的 `num_bigint::BigUint`。測試涵蓋 `N = 1, 2, 4, 8`、零寬度、完整進位／借位鏈、最高 limb 溢位、雙寬度累加與餘數、全部公開算術、CT 選取和相等比較。完整乘積另外以任意精度 oracle 重組高低半部驗證；固定寬度截斷與溢位由模數及完整結果獨立計算。

```text
cargo test -p tc_limb
cargo test -p tc_limb --target i686-pc-windows-msvc
cargo test --workspace
cargo clippy -p tc_limb --all-targets -- -D warnings
cargo fmt -p tc_limb --check
cargo doc -p tc_limb --no-deps
git status --short -- math/tc_bigint
```

最後一行應沒有輸出。i686 測試需要對應的 Rust target 及可用的 MSVC x86 linker／執行環境。公開 API 的範例由 `cargo test` 執行；crate 同時啟用 `missing_docs` 檢查，避免新增未記錄的 API。
