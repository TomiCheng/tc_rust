/// The parameters of the SP 800-108 counter mode, BC's `KdfCounterParameters`.
pub trait KdfCounterParams {
    /// The key `Ki` given to the MAC. Secret material: avoid logging it or keeping copies.
    fn ki(&self) -> &[u8];

    /// Fixed input data hashed before the counter; empty when there is none.
    fn fixed_input_prefix(&self) -> &[u8];

    /// Fixed input data hashed after the counter; empty when there is none.
    fn fixed_input_suffix(&self) -> &[u8];

    /// The counter length `r` in bits: 8, 16, 24 or 32. `init` rejects any other.
    fn counter_bits(&self) -> usize;
}

/// The parameters of the SP 800-108 feedback mode, BC's `KdfFeedbackParameters`.
pub trait KdfFeedbackParams {
    /// The key `Ki` given to the MAC. Secret material: avoid logging it or keeping copies.
    fn ki(&self) -> &[u8];

    /// The IV that stands for `K(0)`; empty when there is none.
    fn iv(&self) -> &[u8];

    /// Fixed input data hashed after the counter; empty when there is none.
    fn fixed_input(&self) -> &[u8];

    /// The counter length `r` in bits, 8, 16, 24 or 32, or `None` for no counter. `init`
    /// rejects any other.
    fn counter_bits(&self) -> Option<usize>;
}

/// The parameters of the SP 800-108 double-pipeline mode, BC's
/// `KdfDoublePipelineIterationParameters`.
pub trait KdfDoublePipelineParams {
    /// The key `Ki` given to the MAC. Secret material: avoid logging it or keeping copies.
    fn ki(&self) -> &[u8];

    /// Fixed input data, which also starts the first pipeline; empty when there is none.
    fn fixed_input(&self) -> &[u8];

    /// The counter length `r` in bits, 8, 16, 24 or 32, or `None` for no counter. `init`
    /// rejects any other.
    fn counter_bits(&self) -> Option<usize>;
}
