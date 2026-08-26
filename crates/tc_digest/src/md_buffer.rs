//! Shared block accumulator for Merkle–Damgård digests, generic over block size.
//!
//! This is the composition-based replacement for Bouncy Castle's abstract
//! `GeneralDigest` (64-byte block) *and* `LongDigest` (128-byte block) base
//! classes — const generics collapse both into one [`MdBuffer<N>`]. Rust models
//! "shared buffering + per-algorithm compression" as *has-a*, not *is-a*: each
//! block digest embeds an [`MdBuffer<N>`] and supplies its compression step as a
//! closure that captures the digest's own register state, so this type never
//! touches algorithm state — only block bookkeeping and padding placement.
//!
//! Length-field semantics differ across families (SHA is big-endian, MD5/RIPEMD
//! little-endian; the field is 64-bit for 64-byte blocks, 128-bit for 128-byte
//! blocks), so [`finish`](MdBuffer::finish) does **not** encode the length
//! itself — the caller passes the already-encoded trailing bytes. The buffer owns
//! only what every family shares: accumulate into N-byte blocks, then pad with
//! `0x80`, zeros, and the caller's length field.

/// A block accumulator for `N`-byte Merkle–Damgård blocks.
///
/// `N` is the compression block size in bytes — 64 for the MD4/MD5/SHA-1/SHA-256/
/// RIPEMD families, 128 for SHA-384/512.
#[derive(Clone)]
pub(crate) struct MdBuffer<const N: usize> {
    /// 累積中的當前 N-byte 區塊。
    block: [u8; N],
    /// block 中已填入的位元組數(0..N)。
    offset: usize,
    /// 至今吃進的訊息總位元組數(不含 padding);供呼叫端算長度欄位。
    byte_count: u64,
}

impl<const N: usize> MdBuffer<N> {
    pub(crate) fn new() -> Self {
        MdBuffer {
            block: [0; N],
            offset: 0,
            byte_count: 0,
        }
    }

    /// 回到初始狀態。
    pub(crate) fn reset(&mut self) {
        self.block = [0; N];
        self.offset = 0;
        self.byte_count = 0;
    }

    /// 目前為止吃進的訊息位元組數(供呼叫端計算位元長度)。
    pub(crate) fn byte_count(&self) -> u64 {
        self.byte_count
    }

    /// 吃進 `input`;每湊滿一個 N-byte 區塊就以 `compress` 處理它。
    ///
    /// 整塊資料直接從 `input` 送進 `compress`,不經過內部緩衝複製。
    pub(crate) fn update(&mut self, mut input: &[u8], mut compress: impl FnMut(&[u8; N])) {
        self.byte_count = self.byte_count.wrapping_add(input.len() as u64);

        // 先補滿當前這塊(若有殘留)。
        if self.offset != 0 {
            let take = (N - self.offset).min(input.len());
            self.block[self.offset..self.offset + take].copy_from_slice(&input[..take]);
            self.offset += take;
            input = &input[take..];
            if self.offset == N {
                compress(&self.block);
                self.offset = 0;
            }
        }

        // 整塊直送。
        while input.len() >= N {
            let (blk, rest) = input.split_at(N);
            compress(blk.try_into().expect("split_at(N) → 恰好 N bytes"));
            input = rest;
        }

        // 存下餘數。
        if !input.is_empty() {
            self.block[..input.len()].copy_from_slice(input);
            self.offset = input.len();
        }
    }

    /// 收尾：補 `0x80`、補零、再把呼叫端編好的 `length_field` 放到區塊尾端,
    /// 把最後一(或兩)塊交給 `compress`。
    ///
    /// `length_field` 是已編碼好的長度位元組(寬度與 endianness 由呼叫端決定:
    /// SHA 為 big-endian、MD5/RIPEMD 為 little-endian;64-byte 塊 8 bytes、
    /// 128-byte 塊 16 bytes)。長度須小於 `N`。
    ///
    /// 此方法**不** reset —— 由呼叫端在寫出摘要後自行 reset(對齊 bc `DoFinal`)。
    pub(crate) fn finish(&mut self, length_field: &[u8], mut compress: impl FnMut(&[u8; N])) {
        debug_assert!(length_field.len() < N, "length field must fit within a block");

        // 補 0x80,再補零到「剛好留下 length_field 空間」的位置;
        // 若當前塊放不下,push 會自動 wrap 出下一塊。
        self.push(0x80, &mut compress);
        while self.offset != N - length_field.len() {
            self.push(0, &mut compress);
        }
        for &b in length_field {
            self.push(b, &mut compress);
        }
        // 此時長度欄位恰好填滿一塊 → 已 compress,offset 回到 0。
    }

    /// 推入單一位元組;湊滿 N 就 compress 並清空。padding 專用(不動 byte_count)。
    fn push(&mut self, byte: u8, compress: &mut impl FnMut(&[u8; N])) {
        self.block[self.offset] = byte;
        self.offset += 1;
        if self.offset == N {
            compress(&self.block);
            self.offset = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// 收集 compress 收到的每個 64-byte 區塊(以 SHA 風格的 big-endian 64-bit 長度收尾)。
    fn collect64(feed: &[&[u8]]) -> Vec<[u8; 64]> {
        let mut buf = MdBuffer::<64>::new();
        let mut blocks: Vec<[u8; 64]> = Vec::new();
        for chunk in feed {
            buf.update(chunk, |b| blocks.push(*b));
        }
        let bit_len = buf.byte_count() << 3;
        buf.finish(&bit_len.to_be_bytes(), |b| blocks.push(*b));
        blocks
    }

    #[test]
    fn empty_message_one_block() {
        let blocks = collect64(&[b""]);
        assert_eq!(blocks.len(), 1);
        let b = blocks[0];
        assert_eq!(b[0], 0x80);
        assert!(b[1..].iter().all(|&x| x == 0)); // 長度 0
    }

    #[test]
    fn abc_padding_layout() {
        let blocks = collect64(&[b"abc"]);
        assert_eq!(blocks.len(), 1);
        let b = blocks[0];
        assert_eq!(&b[..3], b"abc");
        assert_eq!(b[3], 0x80);
        assert!(b[4..56].iter().all(|&x| x == 0));
        // 位元長度 = 24 = 0x18,big-endian 落在最後 8 byte。
        assert_eq!(&b[56..64], &[0, 0, 0, 0, 0, 0, 0, 0x18]);
    }

    #[test]
    fn spills_to_second_block_when_tail_in_length_area() {
        let msg = [0x61u8; 56];
        let blocks = collect64(&[&msg]);
        assert_eq!(blocks.len(), 2);
        assert_eq!(&blocks[0][..56], &msg[..]);
        assert_eq!(blocks[0][56], 0x80);
        assert!(blocks[0][57..].iter().all(|&x| x == 0));
        assert!(blocks[1][..56].iter().all(|&x| x == 0));
        // 56*8 = 448 = 0x01C0
        assert_eq!(&blocks[1][56..64], &[0, 0, 0, 0, 0, 0, 0x01, 0xC0]);
    }

    #[test]
    fn chunked_update_matches_whole() {
        let msg: Vec<u8> = (0..130).map(|i| i as u8).collect();
        let whole = collect64(&[&msg]);
        let chunked = collect64(&[&msg[..1], &msg[1..64], &msg[64..70], &msg[70..]]);
        assert_eq!(whole, chunked);
        // 130 = 2*64 + 2 → 2 整塊 + 1 padding 塊。
        assert_eq!(whole.len(), 3);
    }

    /// 驗證 const generic 在 128-byte 塊(SHA-512 風格,16-byte big-endian 長度)也成立。
    #[test]
    fn block_size_128_empty() {
        let mut buf = MdBuffer::<128>::new();
        let mut blocks: Vec<[u8; 128]> = Vec::new();
        let bit_len = (buf.byte_count() as u128) << 3;
        buf.finish(&bit_len.to_be_bytes(), |b| blocks.push(*b));
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0][0], 0x80);
        assert!(blocks[0][1..].iter().all(|&x| x == 0)); // 128-bit 長度 0,全零尾
    }
}
