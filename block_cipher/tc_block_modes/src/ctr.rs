mod fixed_mode;
#[cfg(feature = "alloc")]
mod mode;

pub use fixed_mode::FixedSicBlockCipher;
#[cfg(feature = "alloc")]
pub use mode::SicBlockCipher;

/// Allocation-free CTR mode with an `N`-byte block; the same type as
/// [`FixedSicBlockCipher`].
pub type FixedCtrBlockCipher<C, const N: usize> = FixedSicBlockCipher<C, N>;

/// Runtime-sized CTR mode; the same type as [`SicBlockCipher`].
#[cfg(feature = "alloc")]
pub type CtrBlockCipher<C> = SicBlockCipher<C>;

/// 把整個區塊當大端序整數加一，溢位時繞回。計數器是公開值，提早跳出不構成側通道。
fn increment_be(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}
