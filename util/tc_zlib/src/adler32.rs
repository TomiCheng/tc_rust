//! Adler-32 checksum — port of `adler32.c` from zlib v1.3.2.
// Dead-code warnings are expected until adler32 is wired into DeflateState / InflateState.
#![allow(dead_code)]
//!
//! Adler-32 is a fast checksum algorithm defined in RFC 1950 §8.2.
//! It is significantly faster than CRC-32 for most inputs while
//! providing reasonable error detection.
//!
//! # Algorithm
//!
//! Two running sums are maintained over the input bytes:
//! - `s1`: simple sum of all bytes, initialised to 1
//! - `s2`: sum of all intermediate `s1` values, initialised to 0
//!
//! Both sums are reduced modulo `BASE` (65521, the largest prime less
//! than 2¹⁶). The final checksum is `(s2 << 16) | s1`.
//!
//! # Examples
//!
//! ```ignore
//! // "hello world" → 0x1A0B045D
//! let checksum = update(1, b"hello world");
//! assert_eq!(checksum, 0x1A0B_045D);
//!
//! // split processing yields the same result
//! let a1 = update(1, b"hello ");
//! let a2 = update(1, b"world");
//! let combined = combine(a1, a2, b"world".len() as u64);
//! assert_eq!(combined, checksum);
//! ```

/// Largest prime below 2¹⁶ — the modulus used in Adler-32.
const BASE: u32 = 65521;

/// Maximum number of bytes to accumulate before reducing modulo `BASE`.
///
/// At this chunk size the accumulators cannot overflow a `u32`:
/// `s2_max = NMAX * (NMAX+1)/2 * 255 + (NMAX+1) * (BASE-1)` still fits.
const NMAX: usize = 5552;

/// Updates a running Adler-32 checksum with the bytes in `buf`.
///
/// Pass `adler = 1` to start a new checksum, or the previous return value
/// to extend an existing one.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(update(1, b"hello world"), 0x1A0B_045D);
/// ```
/// 常數時間：只依長度決定圈數，不依內容分支。
pub fn update(adler: u32, buf: &[u8]) -> u32 {
    let mut s1 = adler & 0xffff;
    let mut s2 = adler >> 16;

    for chunk in buf.chunks(NMAX) {
        for &b in chunk {
            s1 += b as u32;
            s2 += s1;
        }
        s1 %= BASE;
        s2 %= BASE;
    }

    (s2 << 16) | s1
}

/// Combines two Adler-32 checksums computed over consecutive byte sequences.
///
/// Given:
/// - `adler1` = checksum of the first sequence
/// - `adler2` = checksum of the second sequence (computed with initial value `1`)
/// - `len2`   = byte length of the second sequence
///
/// Returns the checksum of the concatenation.
///
/// # Examples
///
/// ```ignore
/// let a1 = update(1, b"hello ");
/// let a2 = update(1, b"world");
/// let expected = update(1, b"hello world");
/// assert_eq!(combine(a1, a2, b"world".len() as u64), expected);
/// ```
/// 常數時間：只做固定的算術。
pub fn combine(adler1: u32, adler2: u32, len2: u64) -> u32 {
    let base = BASE as u64;
    let n = len2 % base;

    let s1_a = (adler1 & 0xffff) as u64;
    let s2_a = (adler1 >> 16) as u64;
    let s1_b = (adler2 & 0xffff) as u64;
    let s2_b = (adler2 >> 16) as u64;

    // s1_combined = (s1_a + s1_b - 1) mod BASE
    // The `+ base - 1` keeps the value positive before the mod.
    let s1 = (s1_a + s1_b + base - 1) % base;

    // s2_combined = (s2_a + s2_b + n*s1_a - n) mod BASE
    // `n*s1_a` accounts for the n extra additions of s1_a into s2 when the
    // second sequence was appended.  `-n` corrects for the initial value 1
    // (adler2 was computed starting from 1, not from s1_a).
    let n_s1a = (n * s1_a) % base;
    let neg_n = (base - n % base) % base;
    let s2 = (n_s1a + neg_n + s2_a + s2_b) % base;

    ((s2 << 16) | s1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_one() {
        assert_eq!(update(1, b""), 1);
    }

    #[test]
    fn hello_world() {
        // Reference value from zlib's own test suite.
        assert_eq!(update(1, b"hello world"), 0x1A0B_045D);
    }

    #[test]
    fn incremental_equals_oneshot() {
        let full = update(1, b"The quick brown fox jumps over the lazy dog");
        let part1 = update(1, b"The quick brown fox ");
        let part2 = update(part1, b"jumps over the lazy dog");
        assert_eq!(part2, full);
    }

    #[test]
    fn combine_matches_oneshot() {
        let data1 = b"hello ";
        let data2 = b"world";
        let full = update(1, b"hello world");
        let a1 = update(1, data1);
        let a2 = update(1, data2);
        assert_eq!(combine(a1, a2, data2.len() as u64), full);
    }

    #[test]
    fn combine_empty_second() {
        let a1 = update(1, b"hello");
        let a2 = update(1, b"");
        assert_eq!(combine(a1, a2, 0), a1);
    }

    #[test]
    fn combine_empty_first() {
        let a1 = 1u32; // adler of empty string
        let a2 = update(1, b"world");
        assert_eq!(combine(a1, a2, b"world".len() as u64), a2);
    }
}
