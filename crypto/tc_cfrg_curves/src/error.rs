use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CfrgError {
    NotInitialized,
    NotForSigning,
    NotForVerifying,
    ContextTooLong,
    OutputTooShort,
    AgreementFailed,
}

impl fmt::Display for CfrgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "not initialized",
            Self::NotForSigning => "initialized for verifying, not signing",
            Self::NotForVerifying => "initialized for signing, not verifying",
            Self::ContextTooLong => "the context is longer than 255 bytes",
            Self::OutputTooShort => "the output is too short",
            Self::AgreementFailed => "the shared secret is zero",
        })
    }
}

impl core::error::Error for CfrgError {}
