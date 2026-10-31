use core::fmt;

/// J-PAKE 交換會拒絕的情況。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JPakeError {
    /// 在 `init` 之前就要求交換。
    NotInitialized,
    /// 密碼是空的。
    EmptyPassword,
    /// 密碼模 q 為 0。
    InvalidPassword,
    /// p − 1 不能被 q 整除。
    OrderNotDividing,
    /// g 不在 `[2, p − 1]`。
    GeneratorOutOfRange,
    /// g^q mod p 不是 1。
    GeneratorOrderMismatch,
    /// p 不是質數。
    ModulusNotPrime,
    /// q 不是奇質數。
    OrderNotPrime,
    /// 這一步已經做過。
    RepeatedStep,
    /// 前面的步驟還沒完成。
    PrematureStep,
    /// 對方與自己用了同一個參與者 ID。
    SameParticipantId,
    /// 酬載來自另一個參與者。
    UnexpectedParticipant,
    /// 對方的 g^x4 是 1。
    GxIsOne,
    /// 第二輪的生成元 g^(x1 + x3 + x4) 是 1。
    GaIsOne,
    /// 零知識證明不成立。
    InvalidProof,
    /// 對方的 MacTag 不符：雙方的密碼、雜湊或 MAC 不同。
    MacTagMismatch,
}

impl fmt::Display for JPakeError {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "J-PAKE participant not initialised",
            Self::EmptyPassword => "Password must not be empty.",
            Self::InvalidPassword => "MUST ensure s is not equal to 0 modulo q",
            Self::OrderNotDividing => "p-1 must be evenly divisible by q",
            Self::GeneratorOutOfRange => "g must be in [2, p-1]",
            Self::GeneratorOrderMismatch => "g^q mod p must equal 1",
            Self::ModulusNotPrime => "p must be prime",
            Self::OrderNotPrime => "q must be an odd prime",
            Self::RepeatedStep => "this step of the exchange was already performed",
            Self::PrematureStep => "an earlier step of the exchange must be completed first",
            Self::SameParticipantId => "Both participants are using the same participantId",
            Self::UnexpectedParticipant => "Received payload from incorrect partner",
            Self::GxIsOne => "g^x validation failed.  g^x should not be 1.",
            Self::GaIsOne => "ga is equal to 1.  It should not be.",
            Self::InvalidProof => "Zero-knowledge proof validation failed",
            Self::MacTagMismatch => "Partner MacTag validation failed.",
        })
    }
}

impl core::error::Error for JPakeError {}
