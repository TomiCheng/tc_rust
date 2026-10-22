//! CFRG 曲線：RFC 7748 的 X25519、X448 金鑰協商與 RFC 8032 的 Ed25519、Ed448 簽章，
//! 移植自 Bouncy Castle C#。
//!
//! X25519 金鑰協商：Alice 與 Bob 各自產生金鑰對，交換公鑰後算出同一個共享秘密。
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_cfrg_curves::{KeyGenerationParams, X25519Agreement, X25519KeyPairGenerator};
//!
//! let mut rng = rand::rng();
//! let mut generator = X25519KeyPairGenerator::new();
//! generator.init(KeyGenerationParams::new(&mut rng))?;
//! let (alice_public, alice_private) = generator.generate_key_pair()?;
//! let (bob_public, bob_private) = generator.generate_key_pair()?;
//!
//! // 交換公鑰後，雙方各自計算。
//! let mut alice = X25519Agreement::new();
//! alice.init(&alice_private)?;
//! let mut alice_secret = [0; 32];
//! alice.calculate_agreement(&bob_public, &mut alice_secret)?;
//!
//! let mut bob = X25519Agreement::new();
//! bob.init(&bob_private)?;
//! let mut bob_secret = [0; 32];
//! bob.calculate_agreement(&alice_public, &mut bob_secret)?;
//!
//! assert_eq!(alice_secret, bob_secret);
//! # Ok::<(), tc_cfrg_curves::CfrgError>(())
//! ```
//!
//! Ed25519 簽章：Alice 用私鑰簽章，Bob 用她的公鑰驗章。
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_cfrg_curves::{Ed25519KeyPairGenerator, Ed25519Signer, KeyGenerationParams};
//! use tc_signer::{Signer, SignerInit};
//!
//! let mut rng = rand::rng();
//! let mut generator = Ed25519KeyPairGenerator::new();
//! generator.init(KeyGenerationParams::new(&mut rng))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! let mut signer = Ed25519Signer::new();
//! signer.init(&private_key)?;
//! signer.update(b"attack at dawn")?;
//! let mut signature = [0; 64];
//! signer.generate_signature(&mut signature)?;
//!
//! // Bob 拿到訊息、簽章與 Alice 的公鑰。
//! let mut verifier = Ed25519Signer::new();
//! verifier.init(&public_key)?;
//! verifier.update(b"attack at dawn")?;
//! assert!(verifier.verify_signature(&signature)?);
//! # Ok::<(), tc_cfrg_curves::CfrgError>(())
//! ```

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod agreement;
mod edwards;
mod error;
mod generator;
mod params;
mod rfc7748;
mod rfc8032;
mod signer;

#[cfg(feature = "x448")]
pub use agreement::X448Agreement;
pub use agreement::X25519Agreement;
pub use error::CfrgError;
#[cfg(feature = "ed448")]
pub use generator::Ed448KeyPairGenerator;
#[cfg(feature = "x448")]
pub use generator::X448KeyPairGenerator;
pub use generator::{Ed25519KeyPairGenerator, X25519KeyPairGenerator};
#[cfg(feature = "ed448")]
pub use params::{Ed448PrivateKey, Ed448PublicKey};
pub use params::{
    Ed25519PrivateKey, Ed25519PublicKey, KeyGenerationParams, X25519PrivateKey, X25519PublicKey,
};
#[cfg(feature = "x448")]
pub use params::{X448PrivateKey, X448PublicKey};
#[cfg(feature = "ed448")]
pub use signer::{Ed448PhSigner, Ed448Signer};
pub use signer::{Ed25519CtxSigner, Ed25519PhSigner, Ed25519Signer};
