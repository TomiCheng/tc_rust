# 演算法層盤點

2026-10-31 依 crates.io、tc_rust 工作區與 bc-csharp 原始碼對照整理。

- **已發行**：在 crates.io 上，套件名省略 `tc_` 前綴。
- **孵化池（新架構）**：在 tc_rust，已經接在新的 trait 上（`tc_block_cipher`、crates.io 的
  `tc_digest`、`tc_signer` 等）。
- **孵化池（舊 trait）**：在 tc_rust，還依賴舊的 `tc_cipher`、`tc_crypto`、`tc_params` 或
  `tc_pad`。2026-10-30 最後幾個 MAC 改用新 trait 後，這四個舊 crate 都已刪除，這一欄
  目前全空，保留作為歷史對照。
- **BC 有、還沒做**：bc-csharp 有，這裡還沒有任何對應。

| 類別 | 已發行 | 孵化池（新架構） | 孵化池（舊 trait） | BC 有、還沒做 |
|---|---|---|---|---|
| 區塊加密 | aes、des、aria、camellia、dstu7624、rc_cipher、sm4、threefish、gost28147 | blowfish、cast、seed、serpent、twofish，以及 misc_block_cipher（idea、noekeon、rijndael、skipjack、tea） | — | — |
| 模式／padding | block_modes（ECB、CBC、CFB、OFB、CTR、OpenPGP CFB、GOFB、KCTR）、block_padding、aead_cipher（GCM、CCM、EAX、OCB、GCM-SIV、KCCM） | cts_modes（ECB、CBC 的 CTS） | — | — |
| 串流加密 | chacha、salsa20、hc、rc4_family | — | — | — |
| AEAD 專用演算法 | ascon_aead、grain128_aead、sparkle_aead、chacha_aead | — | — | — |
| 雜湊 | sha、md、keccak、blake、ascon_hash、dstu7564、gost3411、ripemd、skein、sm3、misc_digest（haraka、photon_beetle、sparkle、tiger、whirlpool、xoodyak） | — | — | — |
| MAC | macs、poly1305 | crypto/macs 的 dstu_macs、gost28147_mac、iso9797_mac、kmac、siphash、vmpc_mac | — | — |
| Key wrap | key_wrap、des_wrap、dstu7624_wrap、rc2_wrap | — | — | — |
| 非對稱加密 | rsa、asym_encoding、asym_iso9796 | cfrg_curves（X25519、Ed25519、X448、Ed448）、ec_key、dh_key、elgamal、naccache_stern、sm2（加密） | — | — |
| 簽章 | — | signer、rsa_signer（PKCS#1 v1.5、PSS、X9.31、ISO 9796-2）、dsa（trait、k 計算器、DsaDigestSigner、DER 與 Plain 編碼）、ecdsa_v2 | — | DSA、GOST 3410、ECGOST 3410、DSTU 4145、SM2、ECNR |
| 金鑰協商 | — | agreement、ecdh_v2（ECDH、ECDHC）、dh（基本與 MTI/A0）、ecmqv、ecvko、sm2（金鑰交換）、srp6、jpake、agreement_kdf（WithKdf） | — | — |
| KDF／PBE／亂數 | — | kdf、pbe、pwhash、dh_kek、ecdh_kek、drbg | — | — |
| 數學 | bigint、modular、prime、binpoly、ec_core、fp_curve、fp_custom、f2m_curve、f2m_custom | — | — | — |
| 後量子 | — | — | — | ML-KEM、ML-DSA、SLH-DSA、Falcon、LMS 等，BC 的 `pqc` 整包 |

契約與基礎 crate 另計：block_cipher、buffered_cipher、stream_cipher、aead_cipher、digest、
macs、asym_cipher、key_wrap、zeroize、runtime、constant_time 已發行；signer、agreement 在孵化池。

## 觀察

1. 對稱演算法幾乎都已發行。剩下的是孵化池的 10 個區塊加密與 crypto/macs 的 MAC
   等畢業；它們都已接在新的 trait 上。
2. 非對稱是空洞最大的一側：簽章、金鑰協商都還沒發行；金鑰協商的演算法已齊全，簽章還缺不少。ecdsa_v2
   現在可經 DsaDigestSigner 當成 tc_signer 的簽章器，但 tc_security 的工廠還沒接上。
3. 後量子演算法完全沒做，見下一節。

## 區塊加密的畢業順序

孵化池 `block_cipher/` 的 6 個，先排能解鎖其他 crate 的，再依使用程度。不常用的 IDEA、
Rijndael、Noekeon、SKIPJACK、TEA／XTEA 已在 2026-10-30 合併成 `tc_misc_block_cipher`，
每個演算法一個 feature，也順便避開 crates.io 上 `tc_tea` 被佔用的問題。tc_sm4、
tc_threefish 與 tc_gost28147 已在 2026-10-30 發行，流程照它們走。同日 tc_block_modes
0.1.1 補上 OpenPGP CFB、GOFB、KCTR，`crypto/block_modes` 與舊的 `tc_aes`、`tc_gost28147`
隨之刪除；沒有使用者的另外 10 個舊版也已刪除，它們的新版都在 `block_cipher/`。
`tc_iso9797_mac` 與 `tc_dstu_macs` 改用發行版 `tc_des`、`tc_dstu7624` 與新 trait 後，
最後兩個舊版也已刪除，`crypto/block_cipher` 整個移除。

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

## 雜湊的畢業

雜湊已全部畢業。2026-10-30 從 TomiCheng/tc_digest 發行 0.1.0：sm3、ripemd（照 BC
展開）、dstu7564、gost3411（用發行版 tc_gost28147）、skein（照 BC 完整移植參數，用發行版
tc_threefish）、misc_digest（Haraka、PHOTON-Beetle、ESCH、Tiger、Whirlpool、Xoodyak，
每個演算法一個 feature）。孵化池的 crypto/digest 已刪除，tc_dstu_macs 改用 crates.io 的
tc_dstu7564。

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
