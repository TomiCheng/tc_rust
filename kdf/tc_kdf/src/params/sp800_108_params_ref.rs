use crate::{KdfCounterParams, KdfDoublePipelineParams, KdfFeedbackParams};

/// Borrowed [`KdfCounterParams`]. The caller owns the bytes and wipes them; nothing is checked
/// here, the counter length included.
#[derive(Clone, Copy)]
pub struct KdfCounterParamsRef<'a> {
    ki: &'a [u8],
    prefix: &'a [u8],
    suffix: &'a [u8],
    counter_bits: usize,
}

impl<'a> KdfCounterParamsRef<'a> {
    /// The counter before all fixed input data, as BC's
    /// `KdfCounterParameters(ki, fixedInputDataCounterSuffix, r)`. Constant time.
    pub const fn new(ki: &'a [u8], fixed_input: &'a [u8], counter_bits: usize) -> Self {
        Self::with_prefix(ki, &[], fixed_input, counter_bits)
    }

    /// The counter between `prefix` and `suffix`, as BC's four-argument
    /// `KdfCounterParameters`. Constant time.
    pub const fn with_prefix(
        ki: &'a [u8],
        prefix: &'a [u8],
        suffix: &'a [u8],
        counter_bits: usize,
    ) -> Self {
        Self {
            ki,
            prefix,
            suffix,
            counter_bits,
        }
    }
}

impl KdfCounterParams for KdfCounterParamsRef<'_> {
    /// Constant time: returns the slice without reading it.
    fn ki(&self) -> &[u8] {
        self.ki
    }

    /// Constant time: returns the slice without reading it.
    fn fixed_input_prefix(&self) -> &[u8] {
        self.prefix
    }

    /// Constant time: returns the slice without reading it.
    fn fixed_input_suffix(&self) -> &[u8] {
        self.suffix
    }

    /// Constant time.
    fn counter_bits(&self) -> usize {
        self.counter_bits
    }
}

/// Borrowed [`KdfFeedbackParams`]. The caller owns the bytes and wipes them; nothing is checked
/// here, the counter length included.
#[derive(Clone, Copy)]
pub struct KdfFeedbackParamsRef<'a> {
    ki: &'a [u8],
    iv: &'a [u8],
    fixed_input: &'a [u8],
    counter_bits: Option<usize>,
}

impl<'a> KdfFeedbackParamsRef<'a> {
    /// With an `r`-bit counter after `K(i - 1)`, as BC's `CreateWithCounter`. Constant time.
    pub const fn with_counter(
        ki: &'a [u8],
        iv: &'a [u8],
        fixed_input: &'a [u8],
        counter_bits: usize,
    ) -> Self {
        Self {
            ki,
            iv,
            fixed_input,
            counter_bits: Some(counter_bits),
        }
    }

    /// Without a counter, as BC's `CreateWithoutCounter`. Constant time.
    pub const fn without_counter(ki: &'a [u8], iv: &'a [u8], fixed_input: &'a [u8]) -> Self {
        Self {
            ki,
            iv,
            fixed_input,
            counter_bits: None,
        }
    }
}

impl KdfFeedbackParams for KdfFeedbackParamsRef<'_> {
    /// Constant time: returns the slice without reading it.
    fn ki(&self) -> &[u8] {
        self.ki
    }

    /// Constant time: returns the slice without reading it.
    fn iv(&self) -> &[u8] {
        self.iv
    }

    /// Constant time: returns the slice without reading it.
    fn fixed_input(&self) -> &[u8] {
        self.fixed_input
    }

    /// Constant time.
    fn counter_bits(&self) -> Option<usize> {
        self.counter_bits
    }
}

/// Borrowed [`KdfDoublePipelineParams`]. The caller owns the bytes and wipes them; nothing is
/// checked here, the counter length included.
#[derive(Clone, Copy)]
pub struct KdfDoublePipelineParamsRef<'a> {
    ki: &'a [u8],
    fixed_input: &'a [u8],
    counter_bits: Option<usize>,
}

impl<'a> KdfDoublePipelineParamsRef<'a> {
    /// With an `r`-bit counter after `A(i)`, as BC's `CreateWithCounter`. Constant time.
    pub const fn with_counter(ki: &'a [u8], fixed_input: &'a [u8], counter_bits: usize) -> Self {
        Self {
            ki,
            fixed_input,
            counter_bits: Some(counter_bits),
        }
    }

    /// Without a counter, as BC's `CreateWithoutCounter`. Constant time.
    pub const fn without_counter(ki: &'a [u8], fixed_input: &'a [u8]) -> Self {
        Self {
            ki,
            fixed_input,
            counter_bits: None,
        }
    }
}

impl KdfDoublePipelineParams for KdfDoublePipelineParamsRef<'_> {
    /// Constant time: returns the slice without reading it.
    fn ki(&self) -> &[u8] {
        self.ki
    }

    /// Constant time: returns the slice without reading it.
    fn fixed_input(&self) -> &[u8] {
        self.fixed_input
    }

    /// Constant time.
    fn counter_bits(&self) -> Option<usize> {
        self.counter_bits
    }
}
