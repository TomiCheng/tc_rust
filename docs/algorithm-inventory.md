# 演算法層盤點

2026-10-30 依 crates.io、tc_rust 工作區與 bc-csharp 原始碼對照整理。

- **已發行**：在 crates.io 上，套件名省略 `tc_` 前綴。
- **孵化池（新架構）**：在 tc_rust，已經接在新的 trait 上（`tc_block_cipher`、crates.io 的
  `tc_digest`、`tc_signer` 等）。
- **孵化池（舊 trait）**：在 tc_rust，還依賴舊的 `tc_cipher`、`tc_crypto`、`tc_params` 或
  `tc_pad`。
- **BC 有、還沒做**：bc-csharp 有，這裡還沒有任何對應。

| 類別 | 已發行 | 孵化池（新架構） | 孵化池（舊 trait） | BC 有、還沒做 |
|---|---|---|---|---|
| 區塊加密 | aes、des、aria、camellia、dstu7624、rc_cipher、sm4、threefish、gost28147 | blowfish、cast、seed、serpent、twofish，以及 misc_block_cipher（idea、noekeon、rijndael、skipjack、tea） | crypto/block_cipher 12 個 | — |
| 模式／padding | block_modes（ECB、CBC、CFB、OFB、CTR、OpenPGP CFB、GOFB、KCTR）、block_padding、aead_cipher（GCM、CCM、EAX、OCB） | — | — | CTS、GCM-SIV、KCCM |
| 串流加密 | chacha、salsa20、hc、rc4_family | — | — | — |
| AEAD 專用演算法 | ascon_aead、grain128_aead、sparkle_aead、chacha_aead | — | — | — |
| 雜湊 | sha、md、keccak、blake、ascon_hash | crypto/digest 的 dstu7564、gost3411、ripemd、skein、sm3，以及 misc_digest（haraka、photon_beetle、sparkle、tiger、whirlpool、xoodyak） | — | — |
| MAC | macs、poly1305 | — | crypto/macs 6 個：dstu_macs、gost28147_mac、iso9797_mac、kmac、siphash、vmpc_mac（依賴 tc_crypto） | — |
| Key wrap | key_wrap、des_wrap、dstu7624_wrap、rc2_wrap | — | — | — |
| 非對稱加密 | rsa、asym_encoding、asym_iso9796 | cfrg_curves（X25519、Ed25519、X448、Ed448）、ec_key | — | ElGamal、Naccache-Stern、SM2 加密 |
| 簽章 | — | signer、rsa_signer、dsa、ecdsa_v2 | — | PSS、X9.31、ISO 9796-2、GOST 3410、ECGOST 3410、DSTU 4145、SM2、ECNR |
| 金鑰協商 | — | agreement、ecdh_v2 | — | DH、ECMQV、ECVKO、SM2 金鑰交換、J-PAKE、SRP6 |
| KDF／PBE／亂數 | — | kdf、pbe、pwhash、dh_kek、ecdh_kek、drbg | — | — |
| 數學 | bigint、modular、prime、binpoly、ec_core、fp_curve、fp_custom、f2m_curve、f2m_custom | — | — | — |
| 後量子 | — | — | — | ML-KEM、ML-DSA、SLH-DSA、Falcon、LMS 等，BC 的 `pqc` 整包 |

契約與基礎 crate 另計：block_cipher、buffered_cipher、stream_cipher、aead_cipher、digest、
macs、asym_cipher、key_wrap、zeroize、runtime、constant_time 已發行；signer、agreement 在孵化池。

## 觀察

1. 對稱演算法幾乎都已發行。剩下的是孵化池的 10 個區塊加密等畢業，以及 MAC 6 個
   要先從舊 trait 遷到新的。
2. 非對稱是空洞最大的一側：簽章、金鑰協商都還沒發行，而且缺不少演算法。tc_security
   驗不了 ECDSA，原因之一是 ecdsa_v2 還沒接上 tc_signer。
3. 後量子演算法完全沒做，見下一節。

## 區塊加密的畢業順序

孵化池 `block_cipher/` 的 6 個，先排能解鎖其他 crate 的，再依使用程度。不常用的 IDEA、
Rijndael、Noekeon、SKIPJACK、TEA／XTEA 已在 2026-10-30 合併成 `tc_misc_block_cipher`，
每個演算法一個 feature，也順便避開 crates.io 上 `tc_tea` 被佔用的問題。tc_sm4、
tc_threefish 與 tc_gost28147 已在 2026-10-30 發行，流程照它們走。同日 tc_block_modes
0.1.1 補上 OpenPGP CFB、GOFB、KCTR，`crypto/block_modes` 與舊的 `tc_aes`、`tc_gost28147`
隨之刪除。`crypto/block_cipher` 剩下的 12 個裡，舊的 `tc_des`、`tc_dstu7624` 還被
`tc_iso9797_mac`、`tc_dstu_macs` 使用，其他 10 個已沒有使用者。

| # | crate | 理由 |
|---|---|---|
| 1 | seed | 韓國標準，TLS 與 CMS 會用到 |
| 2 | cast | CAST5 與 CAST6；CAST5 是 OpenPGP 的舊預設，CMS 也有 OID |
| 3 | blowfish | 舊系統很常見 |
| 4 | twofish | VeraCrypt、KeePass |
| 5 | serpent | 含 Tnepres；VeraCrypt |
| 6 | misc_block_cipher | IDEA（舊 OpenPGP）、Rijndael（非 128 位元區塊）、Noekeon、SKIPJACK、TEA／XTEA |

每個 crate 畢業時都要決定要不要加 `rustcrypto` feature。原則照 SM4：RustCrypto 版本洩漏
較少，或速度差很多時才加。

## 雜湊的遷移與畢業順序

crypto/digest 都已改用 crates.io 的 `tc_digest`，名稱改由 `Display` 提供，本地的
`tc_digest` 已刪除。`tc_skein` 另外改用發行版 `tc_threefish`（`ThreefishPortableEngine`），
`tc_gost3411` 改用發行版 `tc_gost28147` 與 `tc_block_cipher`，不再依賴 `tc_cipher`。不常用的 Haraka、
PHOTON-Beetle、ESCH、Tiger、Whirlpool、Xoodyak 已在 2026-10-30 合併成 `tc_misc_digest`，
每個演算法一個 feature；國家標準與常用的維持獨立。

| # | crate | 理由 |
|---|---|---|
| 1 | sm3 | 中國標準，SM2 簽章與金鑰交換都要用；TLS 1.3（RFC 8998）；沒有阻擋 |
| 2 | ripemd | RIPEMD-160 很常見（Bitcoin、OpenPGP、舊憑證）；沒有阻擋 |
| 3 | dstu7564 | Kupyna，烏克蘭標準，與 DSTU 7624、4145 配套 |
| 4 | gost3411 | 已改用發行版 tc_gost28147，可直接搬去發行 |
| 5 | skein | 已遷到新 trait 與發行版 tc_threefish，可直接搬去發行 |
| 6 | misc_digest | Whirlpool（ISO、VeraCrypt）、Tiger（舊系統）、ESCH／Xoodyak／PHOTON-Beetle（NIST 輕量密碼決賽，未入選）、Haraka（標準化前的 SPHINCS+） |

都可以直接搬到 TomiCheng/tc_digest 發行。tc_ascon_hash 是入選者，維持獨立。

## 後量子

bc-csharp 的後量子程式分在兩處。行數為約略值。

### 已成為 FIPS 標準，在 BC 主程式（`crypto/`）

| 演算法 | 標準 | 行數 |
|---|---|---:|
| ML-KEM | FIPS 203 | 1,800 |
| ML-DSA | FIPS 204 | 1,600 |
| SLH-DSA | FIPS 205 | 1,200 |

加上 `crypto/parameters`、`crypto/generators` 裡的對應類別，三者合計約 5,000 行。

### `pqc/` 子專案（約 76,000 行）

| 狀態 | 演算法 | 行數 |
|---|---|---:|
| 已標準化或即將標準化 | LMS／HSS（SP 800-208，有狀態的雜湊簽章） | 4,700 |
| | Falcon（FN-DSA，FIPS 206 草案） | 9,100 |
| | HQC（2025 年 NIST 選定，標準未定） | 1,600 |
| 標準化前的舊版本 | crystals（舊 Kyber／Dilithium）、sphincsplus（舊 SPHINCS+） | 6,000 |
| 競賽候選，多數未入選 | Classic McEliece、FrodoKEM、NTRU、NTRU Prime、Saber、BIKE | 10,000 |
| 已淘汰 | Picnic | 42,000（大多是常數表） |

### 建議順序

1. ML-KEM → ML-DSA → SLH-DSA：都是正式標準，總量不大。ML-KEM 已有規劃：先純軟體，
   量出瓶頸後再做 AVX2 四路平行的 Keccak。SHAKE 由已發行的 tc_keccak 提供。
2. KEM 的契約 crate（BC 的 `IKemEncapsulator`、`IKemDecapsulator`），目前沒有。
3. LMS；Falcon 與 HQC 等標準定案。
4. 舊版本與落選候選不做，除非要和舊系統互通。
