pub(crate) const fn size(n: usize) -> usize {
    (n + 63) >> 6
}

pub(super) fn bit_value(words: &[u64], bit: usize) -> u64 {
    (words[bit >> 6] >> (bit & 63)) & 1
}

pub(super) fn xor_bit_value(words: &mut [u64], bit: usize, value: u64) {
    words[bit >> 6] ^= value << (bit & 63);
}

pub(super) fn mask_top(n: usize, z: &mut [u64]) {
    let partial = n & 63;
    if partial != 0 {
        let last = z.len() - 1;
        z[last] &= (1_u64 << partial) - 1;
    }
}

pub(super) fn debug_assert_product_slack(_n: usize, _tt: &[u64]) {
    #[cfg(debug_assertions)]
    {
        let first_slack = 2 * _n - 1;
        let word = first_slack >> 6;
        let shift = first_slack & 63;
        let mut slack = _tt[word] >> shift;
        for &value in &_tt[word + 1..size(_n) * 2] {
            slack |= value;
        }
        debug_assert_eq!(slack, 0, "extended product contains bits above degree 2n-2");
    }
}

// A product of 2 * size(n) words with every bit up to degree 2n - 2 drawn from `seed` and
// the slack above it clear.
#[cfg(test)]
pub(super) fn product(n: usize, seed: u64) -> alloc::vec::Vec<u64> {
    let mut state = seed;
    let mut tt: alloc::vec::Vec<u64> = (0..size(n) * 2)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        })
        .collect();
    let first_slack = 2 * n - 1;
    tt[first_slack >> 6] &= (1_u64 << (first_slack & 63)) - 1;
    for word in &mut tt[(first_slack >> 6) + 1..] {
        *word = 0;
    }
    tt
}
