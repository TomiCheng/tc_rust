//! 簽章與驗章工廠，對應 BC 的 `ISignatureFactory`、`IVerifierFactory` 與 `Crypto.Operators`。

pub mod calculator;
mod errors;
pub mod factory;
mod traits;

pub use errors::OperatorError;

pub use traits::{
    SignatureCalculator, SignatureFactory, VerifierCalculator, VerifierFactory,
    VerifierFactoryProvider,
};
