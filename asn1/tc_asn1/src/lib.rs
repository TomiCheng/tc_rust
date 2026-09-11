#![no_std]

//! X.690 的編解碼與 ASN.1 通用型別。
//!
//! 這是 ASN.1 支援的最底層：tag、長度，以及 INTEGER、OCTET STRING、BIT STRING、
//! OBJECT IDENTIFIER、SEQUENCE、SET 這些通用型別。**結構定義不在這裡** ——
//! `SubjectPublicKeyInfo`、PKCS#8、`ECDSA-Sig-Value` 之類屬於上層 crate。
//!
//! 分界的理由是變動速度不同：X.690 不會改，而想支援的 ASN.1 模組沒有盡頭
//! （CMS、OCSP、TSP…）。兩者放在一起，穩定的部分會跟著不穩定的部分改版。
//!
//! # 中間層
//!
//! 具名結構不直接寫位元組，中間隔一層 [`Asn1Object`]：
//!
//! ```text
//! 具名結構  →  Asn1Object  →  位元組
//! 位元組    →  Asn1Object  →  具名結構
//! ```
//!
//! 這讓兩件事各自獨立：結構對映不必知道編碼規則，編碼規則不必知道有哪些結構。
//! N 個結構配 M 種規則要寫 N + M 份程式碼，不是 N × M。異質的 `SET` 也因此
//! 只是一個 `Vec<Asn1Object>`，不需要 trait 物件。
//!
//! 這是 Bouncy Castle 的分法（`ToAsn1Object()` 加 `GetEncoding(encoding)`），
//! 移植對照接得回去。
//!
//! # 編碼要選規則，解碼不用
//!
//! [`TryEncode`] 收 [`EncodingType`]：同一個值在 BER、DL、DER 下有不同寫法。
//!
//! [`TryDecode`] 不收：讀進來的位元組只有一種讀法，一律照 BER（三者的超集）
//! 寬鬆解。需要「輸入必須是 DER」的地方用往返比較 —— 重編成 DER 後與原位元組
//! 相等才算數。這成立是因為 DER 的定義就是一個值只有一種合法編碼，所以不需要
//! 第二個嚴格解碼器。
//!
//! **驗簽章要用原始位元組**，不能用重編出來的。理由見 [`TryDecode`]。
//!
//! # 值是擁有的
//!
//! 解出來的值擁有自己的位元組，不借用輸入。代價是解析時每個欄位複製一次；
//! 換到的是沒有生命期傳染、可以留著用、以及秘密材料歸零時有東西可歸零。
//!
//! 本 crate 無條件依賴 `alloc`。零配置的設定考慮過但沒有買家 —— 會用到 ASN.1
//! 的 crate（RSA、ECDSA）本來就無條件需要 `alloc`，為了它們用不到的性質扭曲
//! 整個設計不划算。
//!
//! # INTEGER 不牽扯大數
//!
//! INTEGER 存的是值或位元組，不是大數型別，所以不相依大數 crate。下游剛好接得
//! 上：金鑰參數型別本來就收 `&[u8]`。
//!
//! 無號大端序（大數給的形式）和 DER 的有號最小編碼之間要補符號位元組，這個轉換
//! 由本 crate 負責 —— 漏掉它是 ASN.1 互通最經典的錯。
//!
//! # 尚未涵蓋
//!
//! `UTCTime` / `GeneralizedTime` 還沒做。它們是憑證 `Validity` 才需要的，而且
//! 各自帶著兩位數年份的世紀規則與日曆驗證。等做憑證時再一併處理。

extern crate alloc;

mod asn1_any;
mod asn1_ref;
mod depth;
mod encoding_type;
mod error;
mod traits;
mod universal;

pub use asn1_any::Asn1Any;
pub use asn1_ref::{Asn1Class, Asn1Ref, Children};
pub use depth::Depth;
pub use encoding_type::EncodingType;
pub use error::Asn1Error;
pub use traits::{Encode, TryDecode, TryDecodeContent};
pub use universal::tag;
pub use universal::{
    Arcs, Asn1BitString, Asn1Boolean, Asn1Ia5String, Asn1Integer, Asn1Null, Asn1OctetString,
    Asn1Oid, Asn1PrintableString, Asn1Sequence, Asn1SequenceOf, Asn1Utf8String,
};
