//! 簽章與驗章工廠，對應 BC 的 `ISignatureFactory`、`IVerifierFactory` 與 `Crypto.Operators`。

mod default_signature_calculator;
mod traits;

pub use default_signature_calculator::DefaultSignatureCalculator;
pub use traits::{
    SignatureCalculator, SignatureFactory, VerifierCalculator, VerifierFactory,
    VerifierFactoryProvider,
};
