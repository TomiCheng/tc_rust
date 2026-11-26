# 工單：tc_algo 金鑰型別說明頁（docs/KeyPair/）

## 背景

`crypto/tc_algo/docs/KeyPairGeneration.md` 的 `## Returns` 一節列出每個 key pair generator 回傳的金鑰型別。
`RsaKey` 已有專頁 `crypto/tc_algo/docs/KeyPair/RsaKey.md`（commit fbea1b4），**它是本工單的範本，先完整讀過**。
本工單要為 Returns 其餘的每一條建立同格式的專頁，並把 Returns 的連結改指過去。

## 要建立的頁面

每條 Returns 一頁（公鑰與私鑰同頁），檔名用該條第一個型別名：

| 檔案 | 型別 | 來源 crate | feature |
|---|---|---|---|
| `EcPublicKey.md` | `EcPublicKey<C>`、`EcPrivateKey<C>` | tc_ec_key（crates.io 0.1.0） | 任一曲線 feature：`fp-custom`／`fp-curve`／`f2m-custom`／`f2m-curve` |
| `DhPublicKey.md` | `DhPublicKey`、`DhPrivateKey` | tc_dh_key 0.1.0 | `dh` |
| `MlKemPublicKey.md` | `MlKemPublicKey`、`MlKemPrivateKey` | `crypto/tc_ml_kem` | `ml-kem` |
| `ElGamalPublicKey.md` | `ElGamalPublicKey`、`ElGamalPrivateKey` | tc_elgamal 0.1.0 | `elgamal` |
| `NaccacheSternPublicKey.md` | `NaccacheSternPublicKey`、`NaccacheSternPrivateKey` | `crypto/tc_naccache_stern` | `naccache-stern` |
| `Sm2PublicKey.md` | `Sm2PublicKey`、`Sm2PrivateKey`（`EcPublicKey`／`EcPrivateKey` 在 sm2p256v1 上的別名） | tc_algo `src/params/key/sm2.rs` | `sm2` |
| `Ed25519PublicKey.md` | `Ed25519*`、`Ed448*` | `crypto/tc_cfrg_curves` | `cfrg-curves` |
| `X25519PublicKey.md` | `X25519*`、`X448*` | `crypto/tc_cfrg_curves` | `cfrg-curves` |
| `MlDsaPublicKey.md` | `MlDsaPublicKey`、`MlDsaPrivateKey` | `signer/tc_ml_dsa` | `ml-dsa` |
| `SlhDsaPublicKey.md` | `SlhDsaPublicKey`、`SlhDsaPrivateKey` | `signer/tc_slh_dsa` | `slh-dsa` |
| `DsaPublicKey.md` | `DsaPublicKey`、`DsaPrivateKey` | tc_dsa_signer 0.1.0 | `dsa` |
| `Gost3410PublicKey.md` | `Gost3410PublicKey`、`Gost3410PrivateKey` | `signer/tc_gost3410` | `gost3410` |

crates.io 版的原始碼在 `~/.cargo/registry/src/index.crates.io-*/<crate>-<version>/src`。
**每個欄位、建構子、存取方法都要從原始碼確認，不憑記憶。**

## 每頁的結構（照 RsaKey.md）

1. `# <型別>`，開頭一段：要開哪個 feature、從 `tc_algo::params::key` 匯入哪些型別與 trait、哪個 generator 回傳它。
2. `## Fields` 表：`| Field | What it is | Public key | Private key | Accessor |`，每個欄位一列。
   只描述欄位，**不提任何序列化格式**（PKCS#1、SPKI、RFC 編碼名稱都不寫）。
3. Build 表：`| Build | Gives |`，列出從欄位建回金鑰的建構子（例如 `DhPublicKey::new(y, params)`、
   `MlKemPrivateKey::from_seed(params, seed)`、`EcPublicKey::new(g, &q)`）。建構子回傳 `Result` 的要寫出錯誤時機。
   數值型別（`PaddedBigUint`、曲線點）若 tc_algo 沒轉出，照 RsaKey.md 寫一句「從另一把金鑰讀出的值不需 import」。
4. 一段性質說明：建構時檢查什麼／不檢查什麼、何時 `validate`、私鑰 drop 時是否清除、有沒有 `Debug`／`PartialEq`。
5. `## Read and build a key pair` 範例（規則見下）。
6. `## Use it with an algorithm` 表：`| Rows | Public key | Private key |`，列出吃這種金鑰的 cipher／signer／agreement／KEM 列，
   列名要跟對應的 docs 頁（`Ec.md`、`Dh.md`、`KEM.md`、`Signer.md` 等）表格裡的拼法一致。
7. 頁尾連結：`[Key pair generation](../KeyPairGeneration.md) · [<演算法頁>](../<X>.md) · [<參數頁>](../KeyPairGeneration/<X>.md)`
   （沒有參數頁的 SM2、Ed*、X* 省略第三個）。

## 範例規則（使用者的要求，務必遵守）

- 範例是教學，**不要 `assert`**。
- 流程：用 generator 產生金鑰對 → `as_any().downcast_ref::<T>()` → **用讀出的欄位重新建出 `_public1`、`_private1`**。
  不要另外寫一串 `let _x = key.x();` 的讀值行；讀值直接出現在建構子的參數裡。
- 需要拆 enum 或型別時用 let-else 加 `unreachable!`，不要用 `if let`。
- 數值從既有金鑰 `.clone()` 取得，不要自己造數字。
- EC 頁用 `Secp256r1` 曲線與 `EcSecp256r1PublicKey`／`EcSecp256r1PrivateKey` 別名（見 `src/params/key/named_curves.rs`、
  `docs/KeyPairGeneration/EcKeyGenParams.md`）。
- 範例要能編譯：import 的每一項都要用到。

## 轉出缺口

若範例或 Fields 表需要的建構用型別或存取 trait 不在 `tc_algo::params::key`，就在 `crypto/tc_algo/src/params/key.rs`
補 `pub use`，用跟該型別相同的 `#[cfg(feature = ...)]`。不要轉出整個 crate，也不要轉出 `PaddedBigUint`。
每補一項，在回報裡列出。

## 其他檔案

- `crypto/tc_algo/docs/KeyPairGeneration.md` 的 `## Returns`：每條的連結改指到新頁（`KeyPair/<檔名>.md`）。
- 不要改 `RsaKey.md`，不要動 Returns 以外的段落。

## 慣例

- 文件用英文；一行不超過 100 字元；檔案用 LF。
- 不寫新的 doc comment，不改其他 crate。
- 使用者可能同時在改檔：動手前先 `git status`，只動本工單列出的檔案。

## 驗證

每頁的範例都要實際跑過：把 ```` ```rust ```` 區塊抽成 `crypto/tc_algo/tests/zz_tmp_<名稱>.rs`（`fn main()` 換成
`#[test] fn ...()`），用 `cargo test -p tc_algo --no-default-features --features <feature> --test zz_tmp_<名稱>` 跑，
**通過後刪掉暫時檔**。需要多個 feature 的就一起開。另外跑：

- `cargo build -p tc_algo --all-features`
- `cargo build -p tc_algo --no-default-features`
- `cargo test -p tc_algo --all-features --doc`

DSA 與 GOST 的 domain 產生很慢，暫時測試可以把大小換成最小合法值（DSA 用 `(1024, 160)`、GOST 用 `512`），
但文件裡維持原本的大小。

## 完成條件

- 12 個新頁都在 `crypto/tc_algo/docs/KeyPair/`，範例全部跑過。
- Returns 的 12 條連結都改好。
- 上面三個 cargo 指令都通過、沒有新 warning。
- **不要 commit**。回報：新增的檔案、補了哪些 `pub use`、有疑問或原始碼與本工單不符之處。
