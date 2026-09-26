mod fixed_mode;
#[cfg(feature = "alloc")]
mod mode;

pub use fixed_mode::FixedOfbBlockCipher;
#[cfg(feature = "alloc")]
pub use mode::OfbBlockCipher;
