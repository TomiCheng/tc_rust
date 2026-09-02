//! SP 800-185 §2.3 encoding helpers (`left_encode` / `right_encode` /
//! `encode_string`), ported from Bouncy Castle's `XofUtils`.
//!
//! These length-prefix helpers underlie the SHA-3 derived functions cSHAKE,
//! TupleHash, ParallelHash and KMAC. All lengths are in **bits** unless a name
//! says otherwise.

use alloc::vec::Vec;

/// `left_encode(x)` = `[n, x_big_endian…]`, where `n` is the byte length of `x`
/// (at least 1). The length byte comes **first**.
pub(crate) fn left_encode(value: u64) -> Vec<u8> {
    let mut n: u8 = 1;
    let mut v = value;
    while {
        v >>= 8;
        v != 0
    } {
        n += 1;
    }
    let mut b = Vec::with_capacity(n as usize + 1);
    b.push(n);
    for i in 1..=n {
        b.push((value >> (8 * (n - i))) as u8);
    }
    b
}

/// `right_encode(x)` = `[x_big_endian…, n]`, where `n` is the byte length of `x`.
/// The length byte comes **last**.
pub(crate) fn right_encode(value: u64) -> Vec<u8> {
    let mut n: u8 = 1;
    let mut v = value;
    while {
        v >>= 8;
        v != 0
    } {
        n += 1;
    }
    let mut b = Vec::with_capacity(n as usize + 1);
    for i in 0..n {
        b.push((value >> (8 * (n - i - 1))) as u8);
    }
    b.push(n);
    b
}

/// `encode_string(s)` = `left_encode(bitlen(s)) || s`; the empty string encodes
/// as `left_encode(0)`.
pub(crate) fn encode_string(s: &[u8]) -> Vec<u8> {
    if s.is_empty() {
        return left_encode(0);
    }
    let mut b = left_encode(s.len() as u64 * 8);
    b.extend_from_slice(s);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn left_encode_examples() {
        assert_eq!(left_encode(0), vec![1, 0]);
        assert_eq!(left_encode(168), vec![1, 168]);
        assert_eq!(left_encode(256), vec![2, 1, 0]);
        assert_eq!(left_encode(65536), vec![3, 1, 0, 0]);
    }

    #[test]
    fn right_encode_examples() {
        assert_eq!(right_encode(0), vec![0, 1]);
        assert_eq!(right_encode(256), vec![1, 0, 2]);
        assert_eq!(right_encode(65536), vec![1, 0, 0, 3]);
    }

    #[test]
    fn encode_string_examples() {
        assert_eq!(encode_string(b""), vec![1, 0]);
        // "abc" 3 bytes = 24 bits → left_encode(24)=[1,24] || "abc"。
        assert_eq!(encode_string(b"abc"), vec![1, 24, b'a', b'b', b'c']);
    }
}
