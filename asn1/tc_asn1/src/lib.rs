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
//! 具名結構實作 [`Encode`]，透過共同的 tag、長度與內容契約編碼；解碼時可用
//! [`Asn1Ref`] 借用檢視 TLV，或由 [`TryDecode`] 建立擁有內容的型別。
//! 未知型別可由 [`Asn1Any`] 保留原始編碼。異質結構可用 [`Asn1Object::Set`]，
//! 同質的 [`Asn1SetOf`] 則使用泛型；兩者的 DER 排序規則不同。
//!
//! 沒有 schema 時，用 [`Asn1Object`] 把不認識的緩衝區整棵解開，輸出樹狀文字或
//! 比對節點；尚未建立具名型別時，也能直接拼樹編碼。具名結構仍走 [`Fields`]。
//! [`Asn1Any`] 保留原始位元組，樹則解讀值；已解讀部分重編會正規化，驗簽章
//! 必須用原位元組。樹的 [`Asn1Object::Unknown`] 保留未支援的 universal 編碼，
//! 包括 BER constructed 字元字串與未指派號碼；這些不會正規化，因此樹的往返比較
//! 不能代替完整的 DER 驗證。此樹不歸零，只能存公開資料。
//!
//! # 具名結構怎麼寫
//!
//! [`TryDecodeContent`] 用 [`Fields`] 依序取欄位，最後呼叫 [`Fields::finish`]。
//! 編碼實作 [`SequenceFields`]，再用 [`impl_sequence_encode!`] 產生 [`Encode`]。
//! 標記用 [`Explicit`]／[`Implicit`] 包裝借用值，欄位的省略條件放在清單中。
//! CHOICE 自己實作 [`TryDecode`]；OPTIONAL CHOICE 可用 [`Fields::peek`] 判斷。
//!
//! # 編碼要選規則，解碼不用
//!
//! [`Encode`] 收 [`EncodingType`]，選擇 BER 或 DER。
//!
//! [`TryDecode`] 不收：讀進來的位元組只有一種讀法，一律照 BER（DER 的超集）
//! 寬鬆解。需要「輸入必須是 DER」的地方用往返比較 —— 重編成 DER 後與原位元組
//! 相等才算數。這成立是因為 DER 的定義就是一個值只有一種合法編碼，所以不需要
//! 第二個嚴格解碼器。
//!
//! BER constructed OCTET STRING 與 BIT STRING 會串接成一般字串，重編一律
//! 使用 primitive 形式；[`TryDecode::try_decode_der`] 會用往返比較辨識這項差異。
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
//! # 精確數值、識別碼與時間
//!
//! [`Asn1Real`] 保存任意精度的二進位或十進位表示，不做四則運算；轉成 `f64`
//! 必須精確，不能表示時回傳 [`Asn1Error::InexactValue`]。REAL、TIME 與 DURATION
//! 的 BER 解碼會正規化，重新編碼可能與輸入不同。
//!
//! [`Asn1RelativeOid`] 延續 OID 每個弧為 `u64` 的範圍。兩個 IRI 型別驗證 Unicode
//! 標籤的線路語法，不做登記查詢或 A-label 正規化；相等性比較字串。
//! [`Asn1EmbeddedPdv`] 與 [`Asn1CharacterString`] 攜帶語法識別和原始資料，
//! 不解讀資料指定的傳輸語法。
//!
//! [`Asn1Time`] 包含日期、時間、區間、持續時間與重複區間；有用型別
//! [`Asn1Date`]、[`Asn1TimeOfDay`]、[`Asn1DateTime`]、[`Asn1Duration`] 各自限制
//! 格式。驗證日曆及分量結構，不查詢閏秒公告、時區資料庫或判斷區間先後。
//! 原有 [`Asn1UtcTime`] 與 [`Asn1GeneralizedTime`] 保留原本的契約。
//!
//! 規則依據：[X.680](https://www.itu.int/rec/T-REC-X.680-202102-I/en)、
//! [X.690](https://www.itu.int/rec/T-REC-X.690-202102-I/en) 與
//! [X.660](https://www.itu.int/rec/T-REC-X.660-201107-I/en)。

extern crate alloc;

mod asn1_any;
mod asn1_object;
mod asn1_ref;
mod depth;
mod encoding_type;
mod error;
mod schema;
mod traits;
mod universal;

pub use asn1_any::Asn1Any;
pub use asn1_object::{Asn1Object, Asn1Tagged, TaggedContent};
pub use asn1_ref::{Asn1Class, Asn1Ref, Children};
pub use depth::Depth;
pub use encoding_type::EncodingType;
pub use error::Asn1Error;
pub use schema::{Explicit, Fields, Implicit, SequenceFields};
pub use traits::{Encode, TryDecode, TryDecodeContent};
pub use universal::tag;
pub use universal::{
    Arcs, Asn1BitString, Asn1BmpString, Asn1Boolean, Asn1CharacterString, Asn1Date, Asn1DateTime,
    Asn1Duration, Asn1EmbeddedPdv, Asn1Enumerated, Asn1External, Asn1GeneralString,
    Asn1GeneralizedTime, Asn1GraphicString, Asn1Ia5String, Asn1Integer, Asn1Null,
    Asn1NumericString, Asn1ObjectDescriptor, Asn1OctetString, Asn1Oid, Asn1OidIri,
    Asn1PrintableString, Asn1Real, Asn1RelativeOid, Asn1RelativeOidIri, Asn1SequenceOf, Asn1SetOf,
    Asn1TeletexString, Asn1Time, Asn1TimeOfDay, Asn1UniversalString, Asn1UtcTime, Asn1Utf8String,
    Asn1VideotexString, Asn1VisibleString, ExternalEncoding, PdvIdentification,
};
