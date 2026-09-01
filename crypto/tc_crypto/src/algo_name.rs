//! Algorithm-name abstraction.

/// Writes a cryptographic algorithm's display name without requiring allocation.
pub trait AlgorithmName {
    /// Writes the algorithm name to `output`.
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result;
}
