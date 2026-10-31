/// BC 的 `Cbd.Eta2`：η = 2 的中心二項分布，每 4 個位元組（小端序）產生 8 個係數。常數
/// 時間：只有位元運算與減法。
pub(crate) fn eta2(r: &mut [i16; 256], bytes: &[u8]) {
    for (chunk, coefficients) in bytes.chunks_exact(4).zip(r.chunks_exact_mut(8)) {
        let t = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
        for (j, coefficient) in coefficients.iter_mut().enumerate() {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            *coefficient = a - b;
        }
    }
}

/// BC 的 `Cbd.Eta3`：η = 3 的中心二項分布，每 3 個位元組（小端序）產生 4 個係數。常數
/// 時間：只有位元運算與減法。
pub(crate) fn eta3(r: &mut [i16; 256], bytes: &[u8]) {
    for (chunk, coefficients) in bytes.chunks_exact(3).zip(r.chunks_exact_mut(4)) {
        let t = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], 0]);
        let d = (t & 0x0024_9249) + ((t >> 1) & 0x0024_9249) + ((t >> 2) & 0x0024_9249);
        for (j, coefficient) in coefficients.iter_mut().enumerate() {
            let a = ((d >> (6 * j)) & 0x7) as i16;
            let b = ((d >> (6 * j + 3)) & 0x7) as i16;
            *coefficient = a - b;
        }
    }
}
