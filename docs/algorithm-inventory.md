# 演算法層盤點

2026-10-30 依 crates.io、tc_rust 工作區與 bc-csharp 原始碼對照整理。

- **已發行**：在 crates.io 上，套件名省略 `tc_` 前綴。
- **孵化池（新架構）**：在 tc_rust，已經接在新的 trait 上（`tc_block_cipher`、crates.io 的
  `tc_digest`、`tc_signer` 等）。
- **孵化池（舊 trait）**：在 tc_rust，還依賴舊的 `tc_cipher`、`tc_crypto`、`tc_params`、
  `tc_pad` 或本地的 `tc_digest`。
- **BC 有、還沒做**：bc-csharp 有，這裡還沒有任何對應。

| 類別 | 已發行 | 孵化池（新架構） | 孵化池（舊 trait） | BC 有、還沒做 |
|---|---|---|---|---|
| 區塊加密 | aes、des、aria、camellia、dstu7624、rc_cipher、sm4 | 12 個：blowfish、cast、gost28147、idea、noekeon、rijndael、seed、serpent、skipjack、tea、threefish、twofish | crypto/block_cipher 15 個 | — |
| 模式／padding | block_modes（ECB、CBC、CFB、OFB、CTR）、block_padding、aead_cipher（GCM、CCM、EAX、OCB） | — | crypto/block_modes 5 個 | CTS、GCM-SIV、GOFB、KCCM、KCTR、OpenPGP CFB |
| 串流加密 | chacha、salsa20、hc、rc4_family | — | — | — |
| AEAD 專用演算法 | ascon_aead、grain128_aead、sparkle_aead、chacha_aead | — | — | — |
| 雜湊 | sha、md、keccak、blake、ascon_hash | — | crypto/digest 11 個：dstu7564、gost3411、haraka、photon_beetle、ripemd、skein、sm3、sparkle、tiger、whirlpool、xoodyak | — |
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

1. 對稱演算法幾乎都已發行。剩下的是孵化池的 12 個區塊加密等畢業，以及雜湊 11 個、
   MAC 6 個要先從舊 trait 遷到新的。
2. 非對稱是空洞最大的一側：簽章、金鑰協商都還沒發行，而且缺不少演算法。tc_security
   驗不了 ECDSA，原因之一是 ecdsa_v2 還沒接上 tc_signer。
3. 後量子演算法完全沒做。
