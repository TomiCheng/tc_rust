mod fixed_mode;
#[cfg(feature = "alloc")]
mod mode;

pub use fixed_mode::FixedCfbBlockCipher;
#[cfg(feature = "alloc")]
pub use mode::CfbBlockCipher;
