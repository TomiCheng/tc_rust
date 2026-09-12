# tc_asn1_x509

X.509／PKIX 的具名 ASN.1 結構，建在 `tc_asn1` 的通用型別與 schema helper 上。
本 crate 使用 `no_std` + `alloc`，負責線路表示、結構解碼與編碼；簽章驗證、
信任鏈與網路取得撤銷資訊另屬上層。

## 盤點範圍與狀態

盤點日期：2026-09-12；實作基準：`develop` 的 `3ff90b0`。
BC 對照基準：`bc-csharp` 的 `7fa86379`，`crypto/src/asn1/x509/` 共 **91 個 C# 檔案**，
包含 `qualified/` 與 `sigi/`。另列必需的 `asn1/x500/` 結構與 RFC 5280 中
沒有獨立 BC 類別的項目。BC 舊 API、產生器與輔助類別都列出處置方式，
不表示每個 C# 檔案都要一對一變成 Rust 型別。

這是這個範圍的完整工作清單，不是所有組織私有 extension OID 的窮舉。
下列尚未存在的 Rust 名稱是規劃名稱，實作時再定 API。

| 標記 | 意義 |
| --- | --- |
| **已完成** | 目前原始碼已有實作；不表示相關的上層驗證功能也已完成 |
| **可開工** | 型別尚未實作，但底層編碼能力已足夠 |
| **前置未完成** | 等待本表點名的結構或能力；不是只因缺少密碼演算法就阻擋純 ASN.1 容器 |
| **後續選配** | 核心憑證／CRL 之後的相容性、較少使用的 profile 或便利 API |
| **上層待辦** | 必須規劃，但不放進這個 ASN.1 結構 crate |

## 已完成

| 項目 | 範圍與目前限制 |
| --- | --- |
| `AlgorithmIdentifier`、`AlgorithmParameters` | OID 加上 Absent／Null／Built／Decoded 參數；不驗證各演算法的參數語意 |
| `DigestInfo` | 演算法識別與摘要位元組；這是 PKCS#1 使用的共用結構，不是完整憑證 |
| `Extension` | 單一 extension，含 DEFAULT FALSE 與內層資料解碼入口；尚無 `Extensions` 集合 |
| 四種結構採用 schema helper | 本 crate 的三種結構，以及底層的 `Asn1External`；工單 F 已完成 |

實作入口：[AlgorithmIdentifier](src/algorithm_identifier.rs)、
[DigestInfo](src/digest_info.rs)、[Extension](src/extension.rs)。
`src/lib.rs` 檔頭提到的 `Name`、`Validity`、`SubjectPublicKeyInfo` 是定位描述，
**目前沒有這三個型別的實作**。

## 前置能力盤點

| ID | 狀態 | 能力／缺口 | 影響 |
| --- | --- | --- | --- |
| P1 | 已完成 | INTEGER、ENUMERATED、OID、字串、BIT STRING、OCTET STRING、SEQUENCE OF、SET OF | RDN 的 DER 排序可用 `Asn1SetOf`；不需要等更多基本型別 |
| P2 | 已完成 | `Fields`、`Explicit`、`Implicit`、`SequenceFields`、`impl_sequence_encode!` | 必要／OPTIONAL／DEFAULT／標記已可重用；CHOICE 自行實作 `TryDecode` |
| P3 | **前置未完成** | X.509 時間的完整日曆驗證與跨 UTCTime／GeneralizedTime 的比較 | 現有兩種時間只驗月 1–12、日 1–31，2 月 30 日會通過；完成 `Validity`、CRL 時間與屬性憑證前要補齊。新增的通用 `Asn1Time` 不是 X.509 `Time` 的替代品 |
| P4 | **前置未完成** | Certificate／CRL 模型保存原始 TBS TLV 的設計 | `Asn1Ref::raw()` 已能取得位元組，但尚無憑證模型保存它；驗簽必須用收到的原始 TBS，不能重編後代替 |
| P5 | **前置未完成** | 結構解碼與嚴格 DER／PKIX profile 檢查的邊界 | `Asn1Any` 原樣重發，未知 ANY 或 extension 的往返相等不能證明其內部是 DER；需明列可檢查範圍及未知值政策 |
| P6 | **前置未完成** | DN 比較、字串正規化、IDNA／國際化郵件處理 | 不阻擋 Name／GeneralName 的線路模型；阻擋語意相等、名稱限制及主機名稱比對的完整功能 |
| P7 | **前置未完成** | 演算法 OID／參數規則表與公鑰、簽章格式的轉接 | 不阻擋原始 BIT STRING 的 SPKI；阻擋自動匯入公鑰、選擇驗簽器與完整驗簽 |
| P8 | **待定** | BC 寬鬆相容與 RFC profile 的個別差異 | 例如 BC 接受空 `Extensions`，RFC schema 有非空限制；每個差異要有明確契約及測試，不把 BC 的容忍直接當規格 |

`Asn1Any` 已足以保留未知欄位，因此 **不把尚未存在的通用 `Asn1Object` 當作整批工作的硬前置**。
若後續另做型別化通用物件，可再遷移，不必先建立 derive macro 或 CHOICE trait。

## 1. X.500 名稱與基礎結構

| 項目 | 狀態 | 前置／工作內容 | BC 對照 |
| --- | --- | --- | --- |
| `DirectoryString` | 可開工 | Teletex／Printable／Universal／UTF8／BMP 的 CHOICE；保留原 tag，T.61 不假裝是 UTF-8 | `x500/DirectoryString.cs` |
| `AttributeTypeAndValue` | 可開工 | OID + ANY；未知值保留原編碼，已知值按 OID 解讀 | `x500/AttributeTypeAndValue.cs` |
| `RelativeDistinguishedName`／`Rdn` | **前置未完成** | 等 `AttributeTypeAndValue`；非空 SET OF，使用完整 DER TLV 字典序排序 | `x500/Rdn.cs` |
| `RdnSequence`、`Name` | **前置未完成** | 等 RDN；SEQUENCE OF 保留 RDN 順序，Name 走 CHOICE 解碼；空 subject 是否可用由憑證 profile 判定 | `X509Name.cs` 的線路部分 |
| DN 的文字解析、轉義、顯示 | 後續選配 | 等 Name；保留多值 RDN、OID 名稱映射，定義 RFC 4514 與 BC 文字形式的相容界線 | `X509NameTokenizer.cs`、`X509NameEntryConverter.cs`、`X509DefaultEntryConverter.cs` |
| DN 語意比較與標準化 | **前置未完成** | 等 Name、P6；不能直接把顯示字串或 DER 位元組相等當作名稱相等 | `x500/style/IetfUtilities.cs`、`X509Name.cs` 的比較部分 |
| `Time` | 可開工 | UTCTime／GeneralizedTime CHOICE；建構時的年份選擇與 profile 檢查分清楚；日曆正確性待 P3 | `Time.cs`、`Rfc5280Asn1Utilities.cs`，後者吸收到時間 helper |
| `Validity` | **前置未完成** | 等 Time、P3；notBefore／notAfter，定義順序檢查位置；不綁系統時鐘 | `Validity.cs` |
| `Extensions` | 可開工 | 非空與重複 OID 規則、保留欄位順序、依 OID 查詢、未知 critical 的交付；P8 差異要寫明 | `Extensions.cs`、`X509Extensions.cs` |
| `SubjectPublicKeyInfo` | 可開工 | `AlgorithmIdentifier` + BIT STRING；提供原始公鑰位元組，不先綁演算法後端 | `SubjectPublicKeyInfo.cs` |
| `RsaPublicKey` | 可開工 | modulus／publicExponent 的正整數線路結構；與 SPKI 的封裝分開 | `RSAPublicKeyStructure.cs` |
| `DsaParameters` | 可開工 | p／q／g 的 ASN.1 結構；不以 DSA 簽章後端是否完成為前置 | `DSAParameter.cs` |

## 2. GeneralName 與憑證主體

| 項目 | 狀態 | 前置／工作內容 | BC 對照 |
| --- | --- | --- | --- |
| `OtherName` | 可開工 | type-id + `[0] EXPLICIT ANY`；未知 OID 可保留 | `OtherName.cs` |
| `EdiPartyName` | **前置未完成** | 等 DirectoryString；CHOICE 的標記須按 schema 處理，不能一律 IMPLICIT | `EdiPartyName.cs` |
| `GeneralName` | **前置未完成** | 等 Name、OtherName、EdiPartyName；九個選項見下表 | `GeneralName.cs` |
| `GeneralNames` | **前置未完成** | 等 GeneralName；非空 SEQUENCE OF | `GeneralNames.cs` |
| `TbsCertificate` | **前置未完成** | 等 Name、Validity、SPKI、Extensions、P4；version DEFAULT、serial、issuer／subject、unique IDs 與 `[3] EXPLICIT` extensions | `TBSCertificateStructure.cs`（類別 `TbsCertificateStructure`） |
| `Certificate` | **前置未完成** | 等 TbsCertificate、P4／P5；外層 signatureAlgorithm、signatureValue；演算法一致性與版本限制列入 profile 檢查 | `X509CertificateStructure.cs` |
| `CertificatePair` | **前置未完成** | 等 Certificate；forward／reverse 的 EXPLICIT OPTIONAL，至少一個存在 | `CertificatePair.cs` |

`GeneralName` 九個選項要逐一驗收：

| 選項 | 線路型別／待辦 | 目前前置 |
| --- | --- | --- |
| `[0] otherName` | OtherName | **未完成** |
| `[1] rfc822Name` | IA5String；郵件 profile 與國際化另外處理 | 基本型別已完成；語意檢查待 P6 |
| `[2] dNSName` | IA5String；DNS／IDNA 不只驗 ASCII | 基本型別已完成；語意檢查待 P6 |
| `[3] x400Address` | ORAddress；可先保留不透明 SEQUENCE，但不可宣稱完整解讀 | **X.400 的 ORAddress 及其子結構未完成**；BC 此處也只持有 SEQUENCE |
| `[4] directoryName` | EXPLICIT Name，因內層是 CHOICE | **Name 未完成** |
| `[5] ediPartyName` | EdiPartyName | **未完成** |
| `[6] uniformResourceIdentifier` | IA5String；URI 結構與名稱限制的 host 規則另驗 | 基本型別已完成；語意檢查待 P6 |
| `[7] iPAddress` | OCTET STRING；一般地址與 name constraints 的地址＋遮罩採不同長度規則 | 基本型別已完成；兩種用途的驗證待實作 |
| `[8] registeredID` | OBJECT IDENTIFIER | 基本型別已完成 |

ORAddress 若要完整型別化，還需盤點 BuiltInStandardAttributes、BuiltInDomainDefinedAttributes、
ExtensionAttributes、PersonalName、OrganizationalUnitNames 等 X.400 子結構；
它們不是新增一個字串型別就能完成。先保留不透明值的策略應在 GeneralName API 明示。

## 3. 憑證 extensions

這裡列的是 `Extension.extnValue` 的內層型別或對應的 profile 驗證。
不是每個 extension 都需要獨立 struct；重用 wire shape 時仍要保留 OID 對應與限制。

| 項目 | 狀態 | 前置／工作內容 | BC 對照 |
| --- | --- | --- | --- |
| `SubjectKeyIdentifier` | 可開工 | OCTET STRING 包裝；從公鑰計算識別碼是另一步 | `SubjectKeyIdentifier.cs` |
| `AuthorityKeyIdentifier` | **前置未完成** | 等 GeneralNames；keyIdentifier、authorityCertIssuer、serial 的 OPTIONAL 組合 | `AuthorityKeyIdentifier.cs` |
| `KeyUsage` | 可開工 | named BIT STRING 的位元順序、最短編碼及用途組合；不能只把 bitmask cast 成 byte | `KeyUsage.cs` |
| `KeyPurposeId`、`ExtendedKeyUsage` | 可開工 | EKU OID 表、非空用途集合與未知 OID 保留 | `KeyPurposeId.cs`、`ExtendedKeyUsage.cs` |
| `BasicConstraints` | 可開工 | cA DEFAULT FALSE、非負 pathLenConstraint、兩者關係 | `BasicConstraints.cs` |
| subjectAltName／issuerAltName | **前置未完成** | 等 GeneralNames；與空 subject、critical 的關係由憑證 profile 處理 | 重用 `GeneralNames.cs` |
| `Attribute`／`AttributeTable` | 可開工 | OID + 非空 SET OF ANY；同一 OID 多值與查詢，不自行抹掉未知值 | `Attribute.cs`（類別 `AttributeX509`）、`AttributeTable.cs` |
| `SubjectDirectoryAttributes` | **前置未完成** | 等 Attribute | `SubjectDirectoryAttributes.cs` |
| `GeneralSubtree`、`GeneralSubtrees` | **前置未完成** | 等 GeneralName；minimum DEFAULT 0、maximum OPTIONAL；schema 與 PKIX 限制分開 | `GeneralSubtree.cs`、`GeneralSubtrees.cs` |
| `NameConstraints` | **前置未完成** | 等 GeneralSubtrees；permitted／excluded；真正的 subtree 比對另待 P6 與上層驗證 | `NameConstraints.cs` |
| `CertPolicyId`、`PolicyQualifierId` | 可開工 | policy OID 與 qualifier OID 的共用定義 | `CertPolicyId.cs`、`PolicyQualifierId.cs` |
| `DisplayText` | 可開工 | IA5／Visible／BMP／UTF8 CHOICE 及長度；UserNotice 的 PKIX profile 不等於接受所有 CHOICE | `DisplayText.cs` |
| `NoticeReference`、`UserNotice` | **前置未完成** | 等 DisplayText；organization、noticeNumbers、explicitText | `NoticeReference.cs`、`UserNotice.cs` |
| `PolicyQualifierInfo` | 可開工 | qualifier OID + ANY；CPS URI 可直接做，UserNotice 的型別化解讀等前項 | `PolicyQualifierInfo.cs` |
| `PolicyInformation`、`CertificatePolicies` | **前置未完成** | 等 PolicyQualifierInfo；保留未知 qualifier，驗證非空與 policy 重複限制 | `PolicyInformation.cs`、`CertificatePolicies.cs` |
| `PolicyMappings` | 可開工 | issuerDomainPolicy／subjectDomainPolicy 配對；禁止 anyPolicy 的 profile 限制 | `PolicyMappings.cs`，包含巢狀 `Element` |
| `PolicyConstraints`、`SkipCerts` | 可開工 | 兩個 IMPLICIT 非負整數欄位；至少一個存在 | BC 只有 extension OID，沒有獨立類別，仍需補 |
| `InhibitAnyPolicy` | 可開工 | 非負整數及 OID 綁定 | BC 只有 extension OID，沒有獨立類別，仍需補 |
| `ReasonFlags` | 可開工 | named BIT STRING；供 distribution point 使用 | `ReasonFlags.cs` |
| `DistributionPointName` | **前置未完成** | 等 GeneralNames、RDN；fullName／nameRelativeToCRLIssuer CHOICE | `DistributionPointName.cs` |
| `DistributionPoint`、`CrlDistributionPoints` | **前置未完成** | 等 DistributionPointName、ReasonFlags、GeneralNames | `DistributionPoint.cs`、`CRLDistPoint.cs` |
| freshestCRL | **前置未完成** | 等 CrlDistributionPoints；相同線路型別，另綁 OID | BC `X509Extensions` 的 `FreshestCrl` |
| `AccessDescription`、`AuthorityInformationAccess` | **前置未完成** | 等 GeneralName；accessMethod／accessLocation 與非空集合 | `AccessDescription.cs`、`AuthorityInformationAccess.cs` |
| subjectInfoAccess | **前置未完成** | 等 AccessDescription；與 AIA 共用集合形狀，保留不同用途／OID | BC 只有 OID，可重用 AccessDescription |
| `PrivateKeyUsagePeriod` | **前置未完成** | 等 P3；兩個 IMPLICIT GeneralizedTime。較少使用，排在主線之後 | `PrivateKeyUsagePeriod.cs` |
| `NoRevAvail` | 可開工 | NULL + OID；公鑰憑證適用條件另依 RFC 9608，不能只沿用屬性憑證規則 | BC OID 定義；無獨立類別 |

RFC 5280 的憑證與 CRL 主線對照見 [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)。
UserNotice 的字串 profile 要採 [RFC 6818](https://www.rfc-editor.org/rfc/rfc6818) 更新後的規則，
不要抄原版對 IA5String 的要求。NoRevAvail 的公鑰憑證用途見
[RFC 9608](https://www.rfc-editor.org/rfc/rfc9608)。

## 4. CRL 與 CRL entry

| 項目 | 狀態 | 前置／工作內容 | BC 對照 |
| --- | --- | --- | --- |
| `CrlNumber`、deltaCRLIndicator | 可開工 | 非負 INTEGER；不同 extension OID，共用數值形狀 | `CRLNumber.cs`；deltaCRLIndicator 無獨立類別 |
| `CrlReason` | 可開工 | ENUMERATED 的具名 reason 值；包含 removeFromCRL，處理未使用的值 7 | `CRLReason.cs` |
| invalidityDate、expiredCertsOnCRL | **前置未完成** | 等 P3；GeneralizedTime 與各自 OID／用途 | BC OID 定義，無獨立類別 |
| certificateIssuer | **前置未完成** | 等 GeneralNames；CRL entry 的間接 CRL issuer | BC OID 定義，重用 GeneralNames |
| `IssuingDistributionPoint` | **前置未完成** | 等 DistributionPointName、ReasonFlags；多個 DEFAULT／OPTIONAL 與互斥條件 | `IssuingDistributionPoint.cs` |
| `RevokedCertificate`／`CrlEntry` | **前置未完成** | 等 Time、Extensions、P3；serial、revocationDate、entry extensions | `TBSCertList.cs` 的巢狀 `CrlEntry` |
| `TbsCertList` | **前置未完成** | 等 Name、Time、CrlEntry、Extensions、P3／P4；v2、thisUpdate／nextUpdate、撤銷項目、CRL extensions | `TBSCertList.cs`（類別 `TbsCertificateList`） |
| `CertificateList` | **前置未完成** | 等 TbsCertList、P4／P5；外層簽章包裝，保留原始 TBS | `CertificateList.cs` |
| CRL 的 AKI、issuerAltName、AIA、freshestCRL | **前置未完成** | 等前述內層型別；按 CRL 的 profile 重用，不複製第二套型別 | 對應的憑證 extension 類別 |

## 5. 屬性憑證與授權資料

此組是主線之後的完整工作包，參考 [RFC 5755](https://www.rfc-editor.org/rfc/rfc5755)。
不能把「一般 Certificate 已完成」當作 AttributeCertificate 已完成。

| 項目 | 狀態 | 前置／工作內容 | BC 對照 |
| --- | --- | --- | --- |
| `AttCertValidityPeriod` | **前置未完成** | 等 P3；兩個 GeneralizedTime | `AttCertValidityPeriod.cs` |
| `ObjectDigestInfo` | 可開工 | digestedObjectType ENUMERATED、選用 OID、AlgorithmIdentifier、BIT STRING | `ObjectDigestInfo.cs` |
| `IssuerSerial` | **前置未完成** | 等 GeneralNames；serial、選用 issuerUID | `IssuerSerial.cs` |
| `Holder` | **前置未完成** | 等 IssuerSerial、GeneralNames、ObjectDigestInfo；明確區分版本相容形式 | `Holder.cs` |
| `V2Form`、`AttCertIssuer` | **前置未完成** | 等 GeneralNames、IssuerSerial、ObjectDigestInfo；issuer CHOICE | `V2Form.cs`、`AttCertIssuer.cs` |
| `AttributeCertificateInfo` | **前置未完成** | 等 Holder、AttCertIssuer、AttCertValidityPeriod、Attribute、Extensions | `AttributeCertificateInfo.cs` |
| `AttributeCertificate` | **前置未完成** | 等 AttributeCertificateInfo、P4／P5 的原始簽署內容政策 | `AttributeCertificate.cs` |
| `IetfAttrSyntax` | **前置未完成** | 等 GeneralNames；OID／octets／UTF8 的值選項及一致性 | `IetfAttrSyntax.cs` |
| `RoleSyntax` | **前置未完成** | 等 GeneralName／GeneralNames；roleAuthority、roleName | `RoleSyntax.cs` |
| `Target`、`Targets`、`TargetInformation` | **前置未完成** | 等 GeneralName；targetName／targetGroup 的 EXPLICIT CHOICE。targetCert 分支的 profile 支援範圍另核對，不因 BC 註解列出就宣稱可用 | `Target.cs`、`Targets.cs`、`TargetInformation.cs` |
| auditIdentity、noRevAvail | 可開工 | 分別以 OCTET STRING／NULL 加 OID 建模；授權與撤銷政策仍在上層 | BC OID 定義 |
| `X509Attributes` | 可開工 | 屬性憑證相關的 OID 常數及名稱表 | `X509Attributes.cs` |

## 6. qualified、SigI 與較新憑證結構

以下是 **後續選配工作包**；表中的前置標記仍然有效，不把整包當作已可直接實作。

| 項目 | 狀態 | 前置／工作內容 | BC 對照 |
| --- | --- | --- | --- |
| `TypeOfBiometricData` | 可開工 | 預定 INTEGER／OID CHOICE | `qualified/TypeOfBiometricData.cs` |
| `BiometricData` | **前置未完成** | 等 TypeOfBiometricData；AlgorithmIdentifier、hash、選用 URI；biometricInfo 是其集合 | `qualified/BiometricData.cs` |
| `Iso4217CurrencyCode` | 可開工 | 字母／數字幣別 CHOICE 與長度／範圍 | `qualified/Iso4217CurrencyCode.cs` |
| `MonetaryValue` | **前置未完成** | 等 Iso4217CurrencyCode；amount／exponent，不轉成 f64 | `qualified/MonetaryValue.cs` |
| `QCStatement`、QCStatements | 可開工 | statementId + OPTIONAL ANY 與集合；未知 statement 保留，已知資料逐一解讀 | `qualified/QCStatement.cs` |
| `SemanticsInformation` | **前置未完成** | 等 GeneralName；選用 semanticsIdentifier 與登記機構名稱 | `qualified/SemanticsInformation.cs` |
| qualified OID 表 | 可開工 | 移入相應 OID，不把只有 OID 當成資料型別已完成 | `qualified/RFC3739QCObjectIdentifiers.cs`、`qualified/ETSIQCObjectIdentifiers.cs` |
| `NameOrPseudonym` | **前置未完成** | 等 DirectoryString；pseudonym／姓名 SEQUENCE CHOICE | `sigi/NameOrPseudonym.cs` |
| `PersonalData` | **前置未完成** | 等 NameOrPseudonym、DirectoryString、P3；生日與選用個人欄位 | `sigi/PersonalData.cs` |
| SigI OID 表 | 可開工 | 個人資料等 otherName 的 OID | `sigi/SigIObjectIdentifiers.cs` |
| `SubjectAltPublicKeyInfo` | 可開工 | AlgorithmIdentifier + BIT STRING；不同 OID／用途，獨立於主公鑰欄位 | `SubjectAltPublicKeyInfo.cs` |
| `AltSignatureAlgorithm`、`AltSignatureValue` | 可開工 | 演算法／BIT STRING extension；替代簽章驗證另屬上層 | `AltSignatureAlgorithm.cs`、`AltSignatureValue.cs` |
| `DeltaCertificateDescriptor` | **前置未完成** | 等 Name、Validity、SPKI、Extensions；BC OID 名稱含 `DRAFT_`，實作前先鎖定採用規範與 OID，不能自行當成穩定標準 | `DeltaCertificateDescriptor.cs` |
| logotype、relatedCertificate、instructionCode 等僅 OID 的項目 | 後續選配 | 各自補來源規範及資料模型工單；目前沒有型別化解讀，先保持未知 extension | `X509Extensions.cs` 的 OID；不納入核心完成判準 |

## 7. OID、產生器與 BC 相容層

| 項目 | 狀態 | 處置／前置 | BC 對照 |
| --- | --- | --- | --- |
| X.509／PKIX／extension OID 表 | 可開工 | 按用途集中管理；包括目前只有 OID 的項目，未知 OID 仍可解碼 | `X509ObjectIdentifiers.cs`、`X509Extensions.cs`、`X509Attributes.cs` |
| extension 集合 builder | **前置未完成** | 等 Extensions；新增／取代／重複 OID 政策 | `X509ExtensionsGenerator.cs` |
| v1／v3 TBS certificate builder | **前置未完成** | 等 TbsCertificate；必要欄位與版本限制；可以一個 Rust builder 表達，不必照抄兩個類別 | `V1TBSCertificateGenerator.cs`、`V3TBSCertificateGenerator.cs` |
| v2 CRL builder | **前置未完成** | 等 TbsCertList／CrlEntry | `V2TBSCertListGenerator.cs` |
| 屬性憑證資訊 builder | **前置未完成** | 等 AttributeCertificateInfo | `V2AttributeCertificateInfoGenerator.cs` |
| 舊 `X509Extension`／`X509Extensions` API | 後續選配 | 線路模型以現有 Extension 與待做的 Extensions 為主；只有實際使用者需要時才提供別名／adapter | `X509Extension.cs`、`X509Extensions.cs`，與較新的 `Extension.cs`／`Extensions.cs` 合併盤點 |
| BC 的文字名稱 converter／tokenizer | 後續選配 | 見名稱工作包；不要求 C# 繼承層級的一對一移植 | `X509NameEntryConverter.cs`、`X509DefaultEntryConverter.cs`、`X509NameTokenizer.cs` |

## 8. 不在本 crate 內，但 X.509 整體仍須完成

| 項目 | 狀態 | 尚缺的前置與承諾範圍 |
| --- | --- | --- |
| 公鑰與簽章演算法參數 | 上層待辦 | P7；RSA-PSS 參數（BC `pkcs/RSASSAPSSparams.cs`）、EC named-curve／明示參數、DSA、EdDSA／XDH 等各 profile。一般 AlgorithmIdentifier 能保留它們，不等於已驗證 |
| 公鑰匯入／匯出與驗簽派送 | **前置未完成** | 等 SPKI、Certificate、P4／P7；已有部分密碼原語仍缺 OID、參數及線路格式轉接；不把簽章後端放進 ASN.1 crate |
| 憑證／CRL 簽發 | **前置未完成** | 等 TBS builder、演算法轉接與簽章後端；編碼器本身不持有私鑰 |
| PKIX 路徑建構與驗證 | **前置未完成** | 等憑證模型、驗簽、信任錨、時間、BasicConstraints／KU／EKU、名稱限制與 policy 處理；解碼成功不是憑證有效 |
| CRL／delta CRL／indirect CRL 驗證 | **前置未完成** | 等 CRL 結構、驗簽、分發點、issuer 關係與撤銷狀態合併 |
| 主機名稱與用途驗證 | **前置未完成** | 等 GeneralNames、P6、應用的識別規則；不同於通用證書鏈驗證 |
| OCSP、CSR／PKCS#10、CMS／PKCS#7、PKCS#8／PKCS#12 | 上層待辦 | 各有自己的 ASN.1 schema 與協定；重用本 crate 的識別／名稱型別，另開工作包 |
| PEM／Base64 與讀寫工具 | 上層待辦 | DER／BER 外層文字容器與 I/O；不成為 `no_std` 結構解碼的前置 |
| AIA／CRL／OCSP 網路擷取與快取 | 上層待辦 | 網路、時鐘與儲存策略由應用提供；有 URI extension 不表示會自動下載 |

## 9. RFC 更新追蹤

以下都還要納入對應工作包的驗收，**目前沒有宣稱完成 profile 支援**。
依據 RFC Editor 的 [RFC 5280 更新索引](https://www.rfc-editor.org/info/rfc5280) 盤點：

| 規範 | 需要落到哪個工作包 |
| --- | --- |
| [RFC 6818](https://www.rfc-editor.org/rfc/rfc6818) | UserNotice 的字串要求，以及上層信任錨等澄清 |
| [RFC 9549](https://www.rfc-editor.org/rfc/rfc9549) | 國際化名稱與 name constraints；已取代 RFC 8399 |
| [RFC 9598](https://www.rfc-editor.org/rfc/rfc9598) | OtherName 的 SmtpUTF8Mailbox、IDNA 及郵件比對；已取代 RFC 8398 |
| [RFC 9608](https://www.rfc-editor.org/rfc/rfc9608) | 公鑰憑證 noRevAvail 與撤銷政策 |
| [RFC 9618](https://www.rfc-editor.org/rfc/rfc9618) | 上層 policy validation 更新，不能只做 CertificatePolicies 的 ASN.1 |
| [RFC 9925](https://www.rfc-editor.org/rfc/rfc9925) | Unsigned Certificate 的演算法／profile 與上層使用政策 |
| [RFC 10007](https://www.rfc-editor.org/rfc/rfc10007) | CRL 驗證時 KeyUsage 的處理澄清 |

發行或宣稱符合某個 profile 前，再核對當時的勘誤與更新；表格不自動追蹤新規範。

## 建議實作順序

1. 可獨立先做：OID 表、DirectoryString、AttributeTypeAndValue、SPKI、Extensions，並補 P3。
2. RDN → Name；Time → Validity；OtherName／EdiPartyName → GeneralName → GeneralNames。
3. 保存原始 TBS 的模型與嚴格檢查邊界（P4／P5），再做 TbsCertificate → Certificate。
4. 簡單 extensions 可穿插做；依賴名稱的 AKI、名稱限制、分發點、AIA／SIA 接在 GeneralNames 後。
5. CrlEntry → TbsCertList → CertificateList，並補齊 CRL／entry extensions。
6. 型別與限制穩定後補 builder，再做屬性憑證、qualified／SigI、替代簽章與 delta descriptor。
7. 上層的驗簽、鏈驗證與撤銷處理另驗收，不以本 crate 型別數量代替完成度。

## 每項交付的驗收

- 正常、OPTIONAL 省略、DEFAULT 明寫與省略、錯 tag、缺欄位、多欄位、截斷、Depth 耗盡的測試。
- 明列 EXPLICIT／IMPLICIT 與 CHOICE 的標記方式；集合的順序、重複值和大小限制有測試。
- 固定 DER 向量、解碼／編碼往返、BC 差異測試；未知 ANY／extension 的保留與限制寫入 doc。
- Certificate／CRL 驗收原始 TBS 的保留；外層簽章與公鑰 BIT STRING 的限制分別檢查。
- 結構檢查與 PKIX profile／信任檢查分開記錄；所有資料處理標明變動時間與適用公開值。
- `cargo test -p tc_asn1 -p tc_asn1_x509 --locked`
- `cargo clippy -p tc_asn1 -p tc_asn1_x509 --all-targets --locked -- -D warnings`
- `cargo doc -p tc_asn1 -p tc_asn1_x509 --no-deps --locked`
- 真正的 `no_std` build、fmt 與 LF 檢查；目前兩個 crate 無 `alloc` feature，無條件依賴 alloc。

## 對照來源

- [BC ASN.1 X.509，固定版本](https://github.com/bcgit/bc-csharp/tree/7fa86379/crypto/src/asn1/x509)
- [BC ASN.1 X.500，固定版本](https://github.com/bcgit/bc-csharp/tree/7fa86379/crypto/src/asn1/x500)
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)：憑證、CRL、extensions 與 PKIX profile。
- [RFC 5755](https://www.rfc-editor.org/rfc/rfc5755)：屬性憑證；較早 BC 註解仍會提到 RFC 3281。
