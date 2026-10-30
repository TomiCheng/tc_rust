//! 簽章與驗章工廠，對應 BC 的 `ISignatureFactory`、`IVerifierFactory` 與 `Crypto.Operators`。
//!
//! ```
//! use tc_operator::factory::{Asn1SignatureFactory, Asn1VerifierFactoryProvider};
//! use tc_operator::{SignatureFactory, VerifierFactory, VerifierFactoryProvider};
//! use tc_security::generate;
//!
//! // 1. 產生 Ed25519 金鑰對。
//! let (public_key, private_key) = generate::get_by_name("Ed25519")?
//!     .generator()
//!     .generate_key_pair()?;
//!
//! // 2. 用私鑰簽章；algorithm() 是要寫進憑證的 AlgorithmIdentifier。
//! let signer = Asn1SignatureFactory::new("Ed25519", private_key)?;
//! let signature = signer.sign(b"to be signed")?;
//!
//! // 3. 驗章時演算法來自被驗的資料，公鑰來自呼叫端。
//! let provider = Asn1VerifierFactoryProvider::new(public_key);
//! let verifier = provider.create_verifier_factory(signer.algorithm())?;
//! assert!(verifier.verify(b"to be signed", &signature)?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod calculator;
mod errors;
pub mod factory;
mod traits;

pub use errors::OperatorError;

pub use traits::{
    SignatureCalculator, SignatureFactory, VerifierCalculator, VerifierFactory,
    VerifierFactoryProvider,
};
