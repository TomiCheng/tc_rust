/// The `r`-bit counter `[i]` of SP 800-108, written big-endian in `r / 8` bytes.
#[derive(Clone, Copy)]
pub(super) struct CounterField {
    len: usize,
}

impl CounterField {
    /// `None` unless `bits` is 8, 16, 24 or 32. Constant time.
    pub(super) fn from_bits(bits: usize) -> Option<Self> {
        matches!(bits, 8 | 16 | 24 | 32).then_some(Self { len: bits / 8 })
    }

    /// The most blocks before the counter wraps, `2^r - 1`. Constant time.
    pub(super) fn max_blocks(self) -> u64 {
        (1u64 << (self.len * 8)) - 1
    }

    /// The low `r / 8` bytes of `i`, big-endian, in the front of the returned array; the
    /// length is [`len`](Self::len). Constant time.
    pub(super) fn encode(self, i: u32) -> [u8; 4] {
        let mut bytes = [0; 4];
        bytes[..self.len].copy_from_slice(&i.to_be_bytes()[4 - self.len..]);
        bytes
    }

    /// The counter's length in bytes. Constant time.
    pub(super) fn len(self) -> usize {
        self.len
    }
}

/// The most bytes a function with blocks of `block` bytes may derive: `(2^r - 1) * block`
/// with a counter, unlimited without one.
pub(super) fn max_output(block: usize, counter: Option<CounterField>) -> u64 {
    counter.map_or(u64::MAX, |counter| counter.max_blocks() * block as u64)
}
