//! 簽章與驗章工廠，對應 BC 的 `ISignatureFactory`、`IVerifierFactory` 與 `Crypto.Operators`。

mod traits;

pub use traits::{
    SignatureCalculator, SignatureFactory, VerifierCalculator, VerifierFactory,
    VerifierFactoryProvider,
};
