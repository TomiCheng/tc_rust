use crate::{PemGenerationError, PemObject};

/// 能產生 PEM 物件的型別，對應 BC 的 `PemObjectGenerator`；
/// [`PemWriter::write_object`](crate::PemWriter::write_object) 寫出它產生的物件。
pub trait PemObjectGenerator {
    /// 產生要寫出的物件。實作要標明常數時間或變動時間。
    fn generate(&self) -> Result<PemObject, PemGenerationError>;
}
