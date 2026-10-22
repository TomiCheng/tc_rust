//! SP 800-185 §2.3 encoding helpers (`left_encode` / `right_encode` /
//! `encode_string`), ported from Bouncy Castle's `XofUtils`.
//!
//! These length-prefix helpers underlie the SHA-3 derived functions cSHAKE,
//! TupleHash, ParallelHash and KMAC. All lengths are in **bits** unless a name
//! says otherwise.

use tc_digest::Digest;

/// 編碼結果放在固定長度的陣列裡：u64 最多 8 bytes，加上 1 byte 的長度。
pub(crate) struct Encoded {
    bytes: [u8; 9],
    len: usize,
}

impl Encoded {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

// x 的大端序 bytes 數，至少 1
fn byte_count(value: u64) -> usize {
    (64 - value.leading_zeros() as usize).div_ceil(8).max(1)
}

/// `left_encode(x)` = `[n, x_big_endian…]`, where `n` is the byte length of `x`
/// (at least 1). The length byte comes **first**.
pub(crate) fn left_encode(value: u64) -> Encoded {
    let n = byte_count(value);
    let mut bytes = [0; 9];
    bytes[0] = n as u8;
    bytes[1..=n].copy_from_slice(&value.to_be_bytes()[8 - n..]);
    Encoded { bytes, len: n + 1 }
}

/// `right_encode(x)` = `[x_big_endian…, n]`, where `n` is the byte length of `x`.
/// The length byte comes **last**.
pub(crate) fn right_encode(value: u64) -> Encoded {
    let n = byte_count(value);
    let mut bytes = [0; 9];
    bytes[..n].copy_from_slice(&value.to_be_bytes()[8 - n..]);
    bytes[n] = n as u8;
    Encoded { bytes, len: n + 1 }
}

/// 吸收 `encode_string(s)` = `left_encode(bitlen(s)) || s`：長度前綴與字串分兩次餵入，
/// 不另外串接。空字串就是 `left_encode(0)`。
pub(crate) fn absorb_encoded_string(digest: &mut impl Digest, s: &[u8]) {
    digest.update(left_encode(s.len() as u64 * 8).as_slice());
    digest.update(s);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn left_encode_examples() {
        assert_eq!(left_encode(0).as_slice(), [1, 0]);
        assert_eq!(left_encode(168).as_slice(), [1, 168]);
        assert_eq!(left_encode(256).as_slice(), [2, 1, 0]);
        assert_eq!(left_encode(65536).as_slice(), [3, 1, 0, 0]);
        assert_eq!(
            left_encode(u64::MAX).as_slice(),
            [8, 255, 255, 255, 255, 255, 255, 255, 255]
        );
    }

    #[test]
    fn right_encode_examples() {
        assert_eq!(right_encode(0).as_slice(), [0, 1]);
        assert_eq!(right_encode(256).as_slice(), [1, 0, 2]);
        assert_eq!(right_encode(65536).as_slice(), [1, 0, 0, 3]);
        assert_eq!(
            right_encode(u64::MAX).as_slice(),
            [255, 255, 255, 255, 255, 255, 255, 255, 8]
        );
    }
}
