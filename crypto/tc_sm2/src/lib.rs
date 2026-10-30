//! SM2 公鑰密碼（GM/T 0003），移植自 Bouncy Castle。目前有加密引擎 `SM2Engine`；簽章與
//! 金鑰交換之後加入。
//!
//! SM2 沒有自己的金鑰型別：它用 `tc_ec_key` 的 EC 金鑰，曲線通常是 sm2p256v1。
//!
//! ```
//! use tc_asym_cipher::{AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_fp_custom::named_curves::SM2P256V1;
//! use tc_fp_custom::{SM2P256V1FieldElement, SecPCtCurve};
//! use tc_sm2::{Sm2Engine, Sm2Mode};
//!
//! // sm2p256v1 的常數時間曲線與生成點；收件人產生金鑰對。
//! let curve = SM2P256V1.ct_curve();
//! let g = SM2P256V1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&SecPCtCurve<SM2P256V1FieldElement>>::new();
//! generator.init(EcKeyGenerationParams::new(g, &mut rng))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // 寄件人以公鑰加密，收件人以私鑰解密。
//! let mut encryptor = Sm2Engine::new(Sm2Mode::C1C3C2, rand::rng());
//! encryptor.init(CipherDirection::Encrypt, &public_key)?;
//! let mut ciphertext = vec![0; encryptor.output_size(5)];
//! encryptor.process_block(b"hello", &mut ciphertext)?;
//!
//! let mut decryptor = Sm2Engine::new(Sm2Mode::C1C3C2, rand::rng());
//! decryptor.init(CipherDirection::Decrypt, &private_key)?;
//! let mut plaintext = vec![0; decryptor.output_size(ciphertext.len())];
//! let length = decryptor.process_block(&ciphertext, &mut plaintext)?;
//! assert_eq!(&plaintext[..length], b"hello");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod curve;
mod engine;
mod error;

pub use curve::Sm2Curve;
pub use engine::{Sm2Engine, Sm2Mode};
pub use error::Sm2Error;
