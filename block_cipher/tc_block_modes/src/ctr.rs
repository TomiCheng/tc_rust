mod fixed_mode;
#[cfg(feature = "alloc")]
mod mode;

pub use fixed_mode::FixedCtrBlockCipher;
#[cfg(feature = "alloc")]
pub use mode::CtrBlockCipher;

/// Adds one to the whole block as a big-endian integer, wrapping on overflow.
///
/// Constant time: the carry runs through every byte without branching.
fn increment_be(counter: &mut [u8]) {
    let mut carry = 1_u16;
    for byte in counter.iter_mut().rev() {
        let sum = u16::from(*byte) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
}
