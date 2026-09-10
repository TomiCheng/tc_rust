# tc_rust

把 Bouncy Castle C# 移植成 Rust。以
[bc-csharp](https://github.com/bcgit/bc-csharp) 的結構與測試向量為對照基準。

這裡是**孵化池**：crate 成熟後會搬到各自的正式 repo 發行。因此下列慣例都寫成
crate 自足的形式，不要依賴這個工作區的目錄佈局，也不要在跨 crate 的文件裡
互相指名。

## 慣例

- **註解與 doc 用繁體中文（zh-TW）**；型別名、錯誤訊息、commit message 用英文。
- `src/` 底下**不用 `mod.rs`**，用 `foo.rs` + `foo/`。
- `lib.rs` 只放 `//!`、`mod`、`pub use`，不寫程式。
- 參數型別是 DTO，不驗證內容；有效性一律在 `init` 判定。
- 測試函式名用完整敘述句，說明被驗證的性質，而不是被呼叫的方法名。

## 常數時間

這是密碼學函式庫，時間側通道是正確性的一部分，不是最佳化議題。

- **每個公開方法的 doc 都要標明常數時間或變動時間**，二選一。變動時間的要寫
  「只能用於公開值」並指向對應的常數時間方法。
- 常數時間方法不得呼叫變動時間方法；秘密路徑不得依秘密值分支、索引或決定圈數。
- 攔不住的側通道要如實揭露，不要假裝沒有。
- 這些約定靠讀取自身原始碼的靜態掃描測試守著。加新程式碼時掃描要跟著擴充。

## 驗證

指令見 [README.md](README.md)。`no_std` crate 改動後要跑四種組合：
`--all-features`、`--no-default-features --features alloc`、
`--no-default-features`（build）、以及 clippy 兩種組合加 `-D warnings`。
`cargo test` 一定連到 std，`no_std` 的真實設定只能用 `cargo build` 驗。

效能量測窗口至少 15 秒（`--warm-up-time 3 --measurement-time 15`）；
短窗口在開發機上噪音可達 70%。比較不同後端前先確認契約相同 —— 拿變動時間的
後端跟常數時間的比速度沒有意義。

## 行尾

一律 **LF**。少數檔案在歷史上是 CRLF，改動前先確認該檔現況，否則 diff 會從
幾行變成整檔。Windows 上用腳本改檔特別容易寫成 CRLF。

## Git

commit 用小寫祈使句英文帶範圍（`feat(...)`、`fix(...)`、`perf(...)`）；
主旨說做了什麼，內文說為什麼與取捨。不要加 attribution 行。
**提交前先給使用者看 diff 並等確認。**
