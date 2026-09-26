mod fixed_mode;
#[cfg(feature = "alloc")]
mod mode;

pub use fixed_mode::FixedCbcBlockCipher;
#[cfg(feature = "alloc")]
pub use mode::CbcBlockCipher;
