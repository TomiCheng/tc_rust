# tc_zlib — 施工說明

從 [zlib v1.3.2](https://github.com/madler/zlib/tree/v1.3.2) 的 C 原始碼逐段移植，
對外 API 對應 bc-csharp 的 `ZOutputStream`／`ZInputStream`。**不引入任何外部 crate。**

## 檔案對應

| C 原始碼 | Rust |
|----------|------|
| `deflate.c`／`deflate.h` | `src/deflate.rs` |
| `trees.c`／`trees.h` | `src/deflate/trees.rs`（靜態表由 `trees.h` 轉出） |
| `inflate.c`／`inflate.h` | `src/inflate.rs` |
| `inftrees.c`／`inffixed.h` | `src/inflate/inftrees.rs`（固定表由 `inffixed.h` 轉出） |
| `inffast.c` | `src/inflate/inffast.rs` |
| `adler32.c` | `src/adler32.rs`（等價的簡化版，結果相同） |
| `z_stream` 與回傳碼 | `src/stream.rs` |

## 移植取捨

- 指標改成索引；C 疊在 `pending_buf` 裡的 `sym_buf` 分開放，輸出不變。
- `ct_data` 的兩個 union 保留成 `fc`（Freq／Code）與 `dl`（Dad／Len）兩個欄位。
- 視窗固定 15 位元、`memLevel` 固定 8。
- 不做：gzip、預設字典（遇到 FDICT 回報錯誤）、`deflateParams`、`deflateBound`、
  `Z_PARTIAL_FLUSH`／`Z_BLOCK`／`Z_TREES`、`inflateSync` 等進階 API。

## 驗證

- `tests/data/python/` 是 Python `zlib` 模組（zlib 1.2.12）產生的向量：
  解壓全部要對；壓縮在 level 1–9 要逐 byte 相同，且與緩衝區大小無關。
  level 0 的 stored 區塊切法依輸出緩衝區大小而定，只驗證能解回原文。
- 壞資料（翻轉位元、截斷、尾端多餘資料、FDICT）必須回報錯誤，不能卡住。
