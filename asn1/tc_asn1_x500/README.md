# tc_asn1_x500

X.500 目錄系列的具名 ASN.1 結構：X.501 的 `Name`／`RelativeDistinguishedName`／
`AttributeTypeAndValue`，與 X.520 的 `DirectoryString` 及屬性型別 OID。
X.509 憑證只是借用這些型別當 subject／issuer，所以它們獨立於憑證 crate。
本 crate 使用 `no_std` + `alloc`，只負責線路表示、解碼與編碼；DN 的語意比較
與字串正規化另屬上層。

BC 對照：[`crypto/src/asn1/x500/`](https://github.com/bcgit/bc-csharp/tree/7fa86379/crypto/src/asn1/x500)。

## 狀態

| 項目 | 狀態 |
| --- | --- |
| `DirectoryString` | 已完成 |
| `AttributeTypeAndValue` | 已完成 |
| `RelativeDistinguishedName` | 待做 |
| `Name` | 待做 |
