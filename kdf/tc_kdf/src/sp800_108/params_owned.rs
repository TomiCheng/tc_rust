use alloc::vec::Vec;

use tc_zeroize::Zeroize;

use crate::sp800_108::{KdfCounterParams, KdfDoublePipelineParams, KdfFeedbackParams};

/// Owned [`KdfCounterParams`], wiped on drop; nothing is checked here, the counter length
/// included.
pub struct KdfCounterParamsOwned {
    ki: Vec<u8>,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    counter_bits: usize,
}

impl KdfCounterParamsOwned {
    /// The counter before all fixed input data, as BC's
    /// `KdfCounterParameters(ki, fixedInputDataCounterSuffix, r)`. Takes the vectors without
    /// copying them. Constant time.
    pub const fn new(ki: Vec<u8>, fixed_input: Vec<u8>, counter_bits: usize) -> Self {
        Self::with_prefix(ki, Vec::new(), fixed_input, counter_bits)
    }

    /// The counter between `prefix` and `suffix`, as BC's four-argument
    /// `KdfCounterParameters`. Takes the vectors without copying them. Constant time.
    pub const fn with_prefix(
        ki: Vec<u8>,
        prefix: Vec<u8>,
        suffix: Vec<u8>,
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

impl KdfCounterParams for KdfCounterParamsOwned {
    /// Constant time: returns the slice without reading it.
    fn ki(&self) -> &[u8] {
        &self.ki
    }

    /// Constant time: returns the slice without reading it.
    fn fixed_input_prefix(&self) -> &[u8] {
        &self.prefix
    }

    /// Constant time: returns the slice without reading it.
    fn fixed_input_suffix(&self) -> &[u8] {
        &self.suffix
    }

    /// Constant time.
    fn counter_bits(&self) -> usize {
        self.counter_bits
    }
}

impl Drop for KdfCounterParamsOwned {
    /// Wipes the bytes. Constant time with respect to them.
    fn drop(&mut self) {
        self.ki.zeroize();
        self.prefix.zeroize();
        self.suffix.zeroize();
    }
}

/// Owned [`KdfFeedbackParams`], wiped on drop; nothing is checked here, the counter length
/// included.
pub struct KdfFeedbackParamsOwned {
    ki: Vec<u8>,
    iv: Vec<u8>,
    fixed_input: Vec<u8>,
    counter_bits: Option<usize>,
}

impl KdfFeedbackParamsOwned {
    /// With an `r`-bit counter after `K(i - 1)`, as BC's `CreateWithCounter`. Takes the vectors
    /// without copying them. Constant time.
    pub const fn with_counter(
        ki: Vec<u8>,
        iv: Vec<u8>,
        fixed_input: Vec<u8>,
        counter_bits: usize,
    ) -> Self {
        Self {
            ki,
            iv,
            fixed_input,
            counter_bits: Some(counter_bits),
        }
    }

    /// Without a counter, as BC's `CreateWithoutCounter`. Takes the vectors without copying
    /// them. Constant time.
    pub const fn without_counter(ki: Vec<u8>, iv: Vec<u8>, fixed_input: Vec<u8>) -> Self {
        Self {
            ki,
            iv,
            fixed_input,
            counter_bits: None,
        }
    }
}

impl KdfFeedbackParams for KdfFeedbackParamsOwned {
    /// Constant time: returns the slice without reading it.
    fn ki(&self) -> &[u8] {
        &self.ki
    }

    /// Constant time: returns the slice without reading it.
    fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// Constant time: returns the slice without reading it.
    fn fixed_input(&self) -> &[u8] {
        &self.fixed_input
    }

    /// Constant time.
    fn counter_bits(&self) -> Option<usize> {
        self.counter_bits
    }
}

impl Drop for KdfFeedbackParamsOwned {
    /// Wipes the bytes. Constant time with respect to them.
    fn drop(&mut self) {
        self.ki.zeroize();
        self.iv.zeroize();
        self.fixed_input.zeroize();
    }
}

/// Owned [`KdfDoublePipelineParams`], wiped on drop; nothing is checked here, the counter length
/// included.
pub struct KdfDoublePipelineParamsOwned {
    ki: Vec<u8>,
    fixed_input: Vec<u8>,
    counter_bits: Option<usize>,
}

impl KdfDoublePipelineParamsOwned {
    /// With an `r`-bit counter after `A(i)`, as BC's `CreateWithCounter`. Takes the vectors
    /// without copying them. Constant time.
    pub const fn with_counter(ki: Vec<u8>, fixed_input: Vec<u8>, counter_bits: usize) -> Self {
        Self {
            ki,
            fixed_input,
            counter_bits: Some(counter_bits),
        }
    }

    /// Without a counter, as BC's `CreateWithoutCounter`. Takes the vectors without copying
    /// them. Constant time.
    pub const fn without_counter(ki: Vec<u8>, fixed_input: Vec<u8>) -> Self {
        Self {
            ki,
            fixed_input,
            counter_bits: None,
        }
    }
}

impl KdfDoublePipelineParams for KdfDoublePipelineParamsOwned {
    /// Constant time: returns the slice without reading it.
    fn ki(&self) -> &[u8] {
        &self.ki
    }

    /// Constant time: returns the slice without reading it.
    fn fixed_input(&self) -> &[u8] {
        &self.fixed_input
    }

    /// Constant time.
    fn counter_bits(&self) -> Option<usize> {
        self.counter_bits
    }
}

impl Drop for KdfDoublePipelineParamsOwned {
    /// Wipes the bytes. Constant time with respect to them.
    fn drop(&mut self) {
        self.ki.zeroize();
        self.fixed_input.zeroize();
    }
}
