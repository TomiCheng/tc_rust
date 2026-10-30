//! Naccache-Stern 加密，移植自 Bouncy Castle 的 `NaccacheSternEngine`、
//! `NaccacheSternKeyParameters`、`NaccacheSternPrivateKeyParameters` 與
//! `NaccacheSternKeyPairGenerator`。
//!
//! 結構同 RSA：n = p·q，但 φ(n) 刻意含有一串小質數 pᵢ，其乘積 σ 決定明文的範圍。加密是
//! c = gᵐ mod n；解密對每個 pᵢ 算 c^(φ/pᵢ) 並查表得到 m mod pᵢ，再以中國餘數定理組回 m。
//! 兩段密文相乘，等於明文相加 mod σ（加法同態）。
//!
//! ```
//! use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
//! use tc_bigint::PaddedBigUint;
//! use tc_naccache_stern::{NaccacheSternEngine, NaccacheSternPrivateKey, NaccacheSternPublicKey};
//!
//! // 論文的玩具例子：p = 2·101·3·5·7 + 1，q = 2·191·11·13·17 + 1，g = 131。
//! let (p, q) = (21_211u64, 928_643u64);
//! let n = PaddedBigUint::from(p * q);
//! let phi = PaddedBigUint::from((p - 1) * (q - 1));
//! let g = PaddedBigUint::from(131u8);
//! let sigma_bits = 18; // σ = 3·5·7·11·13·17 = 255255
//! let public_key = NaccacheSternPublicKey::new(g.clone(), n.clone(), sigma_bits);
//! let private_key =
//!     NaccacheSternPrivateKey::new(g, n, sigma_bits, vec![3, 5, 7, 11, 13, 17], phi);
//!
//! let mut encryptor = NaccacheSternEngine::new();
//! encryptor.init(CipherDirection::Encrypt, &public_key)?;
//! let mut ciphertext = vec![0; encryptor.output_block_size()];
//! encryptor.process_block(&[0, 202], &mut ciphertext)?;
//!
//! let mut decryptor = NaccacheSternEngine::new();
//! decryptor.init(CipherDirection::Decrypt, &private_key)?;
//! let mut plaintext = vec![0; decryptor.output_block_size()];
//! let length = decryptor.process_block(&ciphertext, &mut plaintext)?;
//! assert_eq!(&plaintext[..length], &[0, 0, 202]);
//! # Ok::<(), tc_naccache_stern::NaccacheSternError>(())
//! ```

#![no_std]

extern crate alloc;

mod engine;
mod error;
mod key_pair_generator;
mod params;
mod small_primes;

pub use engine::NaccacheSternEngine;
pub use error::NaccacheSternError;
pub use key_pair_generator::NaccacheSternKeyPairGenerator;
pub use params::{
    NaccacheSternKeyGenerationParams, NaccacheSternPrivateKey, NaccacheSternPublicKey,
};
