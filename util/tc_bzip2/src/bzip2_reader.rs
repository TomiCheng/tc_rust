// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This package is based on the work done by Keiron Liddle, Aftex Software
// <keiron@aftexsw.com> to whom the Ant project is very grateful for his
// great code.

//! BZip2 decompression reader.
//!
//! Port of `CBZip2InputStream.cs` from bc-csharp.

use std::io::{self, Read};

use super::bzip2_writer::RNUMS;
use super::constants::*;
use super::crc::Crc;

/// Output state machine for the reverse-RLE pass.
///
/// Because [`BZip2Reader`] is a pull model (bytes are emitted only when
/// [`Read::read`] is called), the inner decode loop must be interruptible.
/// This enum records where in the loop execution was suspended.
///
/// ```text
/// StartBlock   — waiting to read the next block header from the stream
/// RandPartA    — reading the first byte of a new BWT position
/// RandPartB    — accumulating a run (j2 counts identical bytes so far)
/// RandPartC    — in a run of ≥ 4: emitting the repeated byte z more times
/// NoProcess    — end-of-stream reached; no more data to produce
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReaderState {
    StartBlock,
    RandPartA,
    RandPartB,
    RandPartC,
    NoProcess,
}

/// BZip2 decompression reader.
///
/// Wraps an inner [`Read`] containing a bzip2-compressed stream and
/// decompresses it transparently. Implements [`Read`] so it can be used
/// anywhere a readable source is expected.
///
/// # Decompression pipeline
///
/// ```text
/// bzip2 stream
///   → bit reader
///   → Huffman decode (per G_SIZE-symbol group, using the elected table)
///   → inverse MTF (move-to-front)
///   → inverse BWT (using tt[] walking-pointer technique)
///   → inverse RLE (run of ≥ 4 identical bytes followed by repeat count)
///   → original bytes
/// ```
pub struct BZip2Reader<R: Read> {
    inner: R,

    // --- Stream-level state ---
    /// Set when the EOS marker has been seen and CRC verified.
    stream_end: bool,

    // --- Bit input buffer ---
    /// Bits waiting to be consumed, stored MSB-first in the low `bs_live` bits.
    bs_buff: i32,
    /// Number of valid bits currently in `bs_buff` (counts up from 0 to 32).
    bs_live: i32,

    // --- CRC ---
    /// Per-block CRC calculator (reset at the start of each block).
    block_crc: Crc,
    /// Block CRC as stored in the stream header (verified at end of block).
    stored_block_crc: u32,
    /// Combined stream CRC as stored in the EOS marker.
    stored_stream_crc: u32,
    /// Combined stream CRC accumulated from each block's final CRC.
    computed_stream_crc: u32,

    // --- Block header fields ---
    /// BWT origin pointer: which rotation is the original string.
    orig_ptr: usize,
    /// Whether this block was randomised before compression.
    block_randomised: bool,

    // --- BWT inverse reconstruction ---
    /// Combined BWT inverse array: `tt[i] = (next_index << 8) | byte_value`.
    /// Built from `ll8[]` and `unzftab[]` during `setup_block`.
    tt: Vec<u32>,
    /// Walking pointer into `tt[]` — advanced one step per output byte.
    t_pos: usize,
    /// Number of original bytes remaining to emit from the current block.
    count: usize,
    /// Per-byte-value frequency table, used to reconstruct `tt[]`.
    unzftab: [usize; 256],

    // --- Symbol alphabet ---
    /// Which byte values are present in this block.
    in_use: [bool; 256],
    /// Number of distinct byte values in use.
    n_in_use: usize,
    /// Maps MTF rank (0-based) to actual byte value.
    seq_to_unseq: [u8; 256],

    // --- Huffman selector tables ---
    /// Number of Huffman tables used in this block.
    n_groups: usize,
    /// Number of selector entries.
    n_selectors: usize,
    /// `selector[i]` — which Huffman table covers the i-th G_SIZE group
    /// (after MTF-decoding the stored `selector_mtf` values).
    selector: Vec<u8>,
    /// Raw selector values as stored in the stream (MTF-encoded).
    selector_mtf: Vec<u8>,

    // --- Huffman decode tables (one set per group) ---
    /// `limit[g][l]`  — largest Huffman code of length l in group g.
    limit: [[i32; MAX_CODE_LEN + 1]; N_GROUPS],
    /// `base[g][l]`   — first symbol index for codes of length l in group g.
    base: [[i32; MAX_CODE_LEN + 1]; N_GROUPS],
    /// `perm[g][i]`   — symbol at canonical position i in group g.
    perm: [[i32; MAX_ALPHA_SIZE]; N_GROUPS],
    /// Minimum code length for each group.
    min_lens: [i32; N_GROUPS],

    // --- Output state machine ---
    current_state: ReaderState,

    // RLE decode variables — see `SetupRandPartA` / `SetupRandPartB/C` in C#
    /// Previous character seen (used to detect runs of ≥ 4).
    ch_prev: u8,
    /// Run-accumulation counter (1 = first occurrence, 4 = trigger repeat read).
    j2: i32,
    /// Repeat count read from the 5th byte of a run (how many more to emit).
    z: i32,
    /// Most recently decoded BWT character.
    t_ch: u8,
    /// Number of bytes consumed from the BWT block so far.
    t_i: usize,

    // --- Randomisation state (for randomised blocks) ---
    /// Remaining steps until the next bit-flip from RNUMS.
    r_n_to_go: i32,
    /// Current position in the RNUMS table.
    r_t_pos: usize,

    // --- Output byte being assembled for the caller ---
    /// The current output character, or -1 if none is pending.
    current_char: i32,
    /// How many times `current_char` remains to be written to the caller's buffer.
    output_count: usize,
}

impl<R: Read> BZip2Reader<R> {
    /// Open a bzip2-compressed stream for reading.
    ///
    /// Reads and validates the 4-byte stream header (`BZh{n}`) immediately.
    /// Returns an error if the header is missing or malformed.
    /// 變動時間：依資料內容分支，只能用於公開值。
    pub fn new(mut inner: R) -> io::Result<Self> {
        // Read "BZh{n}"
        let mut hdr = [0u8; 4];
        inner.read_exact(&mut hdr)?;

        if hdr[0] != b'B' || hdr[1] != b'Z' || hdr[2] != b'h' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a bzip2 stream",
            ));
        }
        let block_size_100k = match hdr[3] {
            b'1'..=b'9' => (hdr[3] - b'0') as usize,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid bzip2 block size digit",
                ));
            }
        };

        let n = BASE_BLOCK_SIZE * block_size_100k;

        Ok(Self {
            inner,
            stream_end: false,
            bs_buff: 0,
            bs_live: 0,
            block_crc: Crc::new(),
            stored_block_crc: 0,
            stored_stream_crc: 0,
            computed_stream_crc: 0,
            orig_ptr: 0,
            block_randomised: false,
            tt: vec![0u32; n],
            t_pos: 0,
            count: 0,
            unzftab: [0usize; 256],
            in_use: [false; 256],
            n_in_use: 0,
            seq_to_unseq: [0u8; 256],
            n_groups: 0,
            n_selectors: 0,
            selector: vec![0u8; MAX_SELECTORS],
            selector_mtf: vec![0u8; MAX_SELECTORS],
            limit: [[0i32; MAX_CODE_LEN + 1]; N_GROUPS],
            base: [[0i32; MAX_CODE_LEN + 1]; N_GROUPS],
            perm: [[0i32; MAX_ALPHA_SIZE]; N_GROUPS],
            min_lens: [0i32; N_GROUPS],
            current_state: ReaderState::StartBlock,
            ch_prev: 0,
            j2: 0,
            z: 0,
            t_ch: 0,
            t_i: 0,
            r_n_to_go: 0,
            r_t_pos: 0,
            current_char: -1,
            output_count: 0,
        })
    }

    /// 回傳底下的 `R`。
    /// 變動時間：不讀任何資料。
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// 交回底下的 `R`；已讀進但還沒解出的資料就此丟棄。
    /// 變動時間：不讀任何資料。
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> BZip2Reader<R> {
    // -----------------------------------------------------------------------
    // Bit-level input
    // -----------------------------------------------------------------------

    /// Refill `bs_buff` with one byte from the inner reader.
    ///
    /// Shifts the existing bits left by 8 and OR-in the new byte at the bottom,
    /// then increments `bs_live` by 8.
    fn bs_refill(&mut self) -> io::Result<()> {
        let mut byte = [0u8; 1];
        self.inner.read_exact(&mut byte)?;
        self.bs_buff = (self.bs_buff << 8) | byte[0] as i32;
        self.bs_live += 8;
        Ok(())
    }

    /// Read a single bit (0 or 1).
    fn bs_get_bit(&mut self) -> io::Result<i32> {
        self.bs_get_bits(1)
    }

    /// Read `n` bits (1–24) and return them right-aligned in an `i32`.
    ///
    /// Refills from the inner reader one byte at a time until at least `n`
    /// bits are available, then extracts the top `n` bits from the buffer.
    ///
    /// # Buffer layout
    ///
    /// ```text
    ///  bs_buff (i32, 32 bits):
    ///  ┌──────────────────────┬──────────────────────┐
    ///  │  unused (high bits)  │  bs_live valid bits  │
    ///  └──────────────────────┴──────────────────────┘
    ///                          ↑                    ↑
    ///                   bit (bs_live-1)            bit 0
    ///
    ///  Extract n bits:  (bs_buff >> (bs_live - n)) & ((1 << n) - 1)
    /// ```
    fn bs_get_bits(&mut self, n: i32) -> io::Result<i32> {
        debug_assert!((1..=24).contains(&n));
        while self.bs_live < n {
            self.bs_refill()?;
        }
        let v = (self.bs_buff >> (self.bs_live - n)) & ((1 << n) - 1);
        self.bs_live -= n;
        Ok(v)
    }

    /// Read 32 bits as two 16-bit halves (mirrors `bs_put_int32` in the writer).
    fn bs_get_int32(&mut self) -> io::Result<u32> {
        let hi = self.bs_get_bits(16)? as u32;
        let lo = self.bs_get_bits(16)? as u32;
        Ok((hi << 16) | lo)
    }

    // -----------------------------------------------------------------------
    // Block-level decode
    // -----------------------------------------------------------------------

    /// Read the 48-bit block or EOS magic number from the bit stream.
    ///
    /// Returns `true`  if a block magic (`0x314159265359`, π)  was found.
    /// Returns `false` if the EOS magic  (`0x177245385090`, √π) was found.
    /// Returns an error if neither matches (corrupt or truncated stream).
    ///
    /// The magic is read as six consecutive 8-bit values so that it works
    /// correctly regardless of how many bits are currently buffered.
    fn read_block_or_eos_magic(&mut self) -> io::Result<bool> {
        // Read 48 bits as six bytes, MSB first.
        let b0 = self.bs_get_bits(8)? as u8;
        let b1 = self.bs_get_bits(8)? as u8;
        let b2 = self.bs_get_bits(8)? as u8;
        let b3 = self.bs_get_bits(8)? as u8;
        let b4 = self.bs_get_bits(8)? as u8;
        let b5 = self.bs_get_bits(8)? as u8;

        // Block magic: 0x314159265359  (first six hex digits of π)
        if b0 == 0x31 && b1 == 0x41 && b2 == 0x59 && b3 == 0x26 && b4 == 0x53 && b5 == 0x59 {
            return Ok(true);
        }

        // EOS magic: 0x177245385090  (first six hex digits of √π)
        if b0 == 0x17 && b1 == 0x72 && b2 == 0x45 && b3 == 0x38 && b4 == 0x50 && b5 == 0x90 {
            return Ok(false);
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bzip2: invalid block header magic",
        ))
    }

    /// Read and decode the full block header, Huffman tables, and MTF data.
    ///
    /// On entry:  `current_state == StartBlock`.
    /// On exit:   `current_state == RandPartA` (ready to emit bytes),
    ///            or `NoProcess` if the EOS marker was seen.
    ///
    /// # Stream layout consumed here
    ///
    /// ```text
    /// [48 bits]  block magic  0x314159265359  (π)
    ///            — or —
    ///            EOS magic    0x177245385090  (√π)  → end of stream
    /// [32 bits]  stored block CRC
    /// [ 1 bit ]  block_randomised flag
    /// …          get_and_move_to_front_decode (orig_ptr + Huffman + MTF)
    /// ```
    fn init_block(&mut self) -> io::Result<()> {
        let is_block = self.read_block_or_eos_magic()?;

        if !is_block {
            // EOS magic: read the combined stream CRC and verify.
            self.stored_stream_crc = self.bs_get_int32()?;
            self.end_stream()?;
            self.current_state = ReaderState::NoProcess;
            return Ok(());
        }

        // --- Block header ---
        self.stored_block_crc = self.bs_get_int32()?;
        self.block_randomised = self.bs_get_bit()? == 1;

        // Reset randomisation state; the first step is taken in setup_rand_part_a.
        self.r_n_to_go = 0;
        self.r_t_pos = 0;

        // Decode Huffman tables, then decode the MTF-encoded symbol stream.
        // Fills orig_ptr and the raw BWT bytes into tt[] (low 8 bits per entry).
        self.get_and_move_to_front_decode()?;

        // Build the BWT inverse chain (tt[] high bits) and set t_pos = tt[orig_ptr].
        self.setup_block();

        // Prepare per-block CRC accumulator.
        self.block_crc.initialise();

        self.current_state = ReaderState::RandPartA;
        Ok(())
    }

    /// Read the in-use bitmap, selector list, and Huffman code lengths
    /// from the stream; build the `limit`, `base`, and `perm` decode tables.
    ///
    /// # Stream layout consumed here
    ///
    /// ```text
    /// [16 bits]  group-present bitmap  (which of the 16 × 16 groups are used)
    /// [16 bits]  per-byte bitmap       (repeated for each present group)
    /// [ 3 bits]  n_groups  (number of Huffman tables, 2–6)
    /// [15 bits]  n_selectors
    /// unary × n_selectors              selector MTF values
    /// [5 bits] + deltas × n_groups     code lengths (delta-encoded per table)
    /// ```
    fn recv_decoding_tables(&mut self) -> io::Result<()> {
        // --- In-use bitmap (256 bits, encoded as 16 groups of 16) ---
        // The outer 16-bit word says which groups have any set bits.
        let in_use16 = self.bs_get_bits(16)?;
        let mut in_use = [false; 256];
        for i in 0..16i32 {
            if in_use16 & (1 << (15 - i)) != 0 {
                let row = self.bs_get_bits(16)?;
                for j in 0..16i32 {
                    if row & (1 << (15 - j)) != 0 {
                        in_use[(i * 16 + j) as usize] = true;
                    }
                }
            }
        }

        self.n_in_use = 0;
        for (i, &used) in in_use.iter().enumerate() {
            self.in_use[i] = used;
            if used {
                self.seq_to_unseq[self.n_in_use] = i as u8;
                self.n_in_use += 1;
            }
        }

        let alpha_size = self.n_in_use + 2; // +2 for RUNA and RUNB

        // --- Number of Huffman tables and selectors ---
        self.n_groups = self.bs_get_bits(3)? as usize;
        self.n_selectors = self.bs_get_bits(15)? as usize;

        // --- Selector list: unary-coded, each value is the MTF rank ---
        // A unary value of k is stored as k 1-bits followed by one 0-bit.
        for i in 0..self.n_selectors {
            let mut rank = 0usize;
            while self.bs_get_bit()? == 1 {
                rank += 1;
            }
            self.selector_mtf[i] = rank as u8;
        }

        // MTF-decode the selectors: pos[] is the MTF alphabet (table indices).
        let mut pos = [0u8; N_GROUPS];
        for (i, p) in pos.iter_mut().enumerate() {
            *p = i as u8;
        }
        for i in 0..self.n_selectors {
            let j = self.selector_mtf[i] as usize;
            let tmp = pos[j];
            // Shift pos[0..j] right by one, then insert tmp at front.
            pos.copy_within(0..j, 1);
            pos[0] = tmp;
            self.selector[i] = tmp;
        }

        // --- Code lengths for each Huffman table (delta-encoded) ---
        // Start value: 5 bits.  For each symbol: read bits until 0 is seen;
        // each 1 followed by 0 decrements, each 1 followed by 1 increments.
        let mut len = [[0i32; MAX_ALPHA_SIZE]; N_GROUPS];
        for len_t in len.iter_mut().take(self.n_groups) {
            let mut curr = self.bs_get_bits(5)?;
            for cell in len_t.iter_mut().take(alpha_size) {
                loop {
                    if self.bs_get_bit()? == 0 {
                        break;
                    }
                    if self.bs_get_bit()? == 0 {
                        curr += 1;
                    } else {
                        curr -= 1;
                    }
                }
                *cell = curr;
            }
        }

        // --- Build Huffman decode tables (limit, base, perm) ---
        for (t, len_t) in len.iter().enumerate().take(self.n_groups) {
            let mut min_len = 32i32;
            let mut max_len = 0i32;
            for &l in len_t.iter().take(alpha_size) {
                if l > max_len {
                    max_len = l;
                }
                if l < min_len {
                    min_len = l;
                }
            }
            Self::hb_create_decode_tables(
                &mut self.limit[t],
                &mut self.base[t],
                &mut self.perm[t],
                len_t,
                min_len,
                max_len,
                alpha_size,
            );
            self.min_lens[t] = min_len;
        }

        Ok(())
    }

    /// Build canonical Huffman decode tables from an array of code lengths.
    ///
    /// Mirrors `HbCreateDecodeTables` from bc-csharp.
    ///
    /// * `perm`  — symbols in canonical (length-first) order.
    /// * `base`  — base code value for each length level.
    /// * `limit` — largest code value at each length level.
    fn hb_create_decode_tables(
        limit: &mut [i32; MAX_CODE_LEN + 1],
        base: &mut [i32; MAX_CODE_LEN + 1],
        perm: &mut [i32; MAX_ALPHA_SIZE],
        length: &[i32],
        min_len: i32,
        max_len: i32,
        alpha_size: usize,
    ) {
        // perm[]: symbols listed in ascending code-length order (canonical order).
        let mut pp = 0;
        for i in min_len..=max_len {
            for (j, &l) in length.iter().enumerate().take(alpha_size) {
                if l == i {
                    perm[pp] = j as i32;
                    pp += 1;
                }
            }
        }

        // base[l]: cumulative count of symbols with length < l.
        base.fill(0);
        for &l in length.iter().take(alpha_size) {
            base[l as usize + 1] += 1;
        }
        for i in 1..=MAX_CODE_LEN {
            base[i] += base[i - 1];
        }

        // limit[l]: the largest Huffman code value of length l.
        limit.fill(0);
        let mut vec = 0i32;
        for i in min_len..=max_len {
            vec += base[i as usize + 1] - base[i as usize];
            limit[i as usize] = vec - 1;
            vec <<= 1;
        }

        // Adjust base[] so that  symbol_index = perm[code - base[len]].
        for i in (min_len + 1)..=max_len {
            base[i as usize] = ((limit[(i - 1) as usize] + 1) << 1) - base[i as usize];
        }
    }

    /// Decode the MTF-encoded symbol stream using the Huffman tables.
    ///
    /// Reads `orig_ptr`, calls `recv_decoding_tables`, then decodes each
    /// Huffman symbol and reverses the MTF transform, writing raw BWT bytes
    /// into the low 8 bits of `tt[]`.  `unzftab[b]` accumulates how many
    /// times byte `b` appears, ready for `setup_block` to use.
    ///
    /// After this call `self.count` holds the number of bytes in the block.
    fn get_and_move_to_front_decode(&mut self) -> io::Result<()> {
        self.orig_ptr = self.bs_get_bits(24)? as usize;
        self.recv_decoding_tables()?;

        let eob = self.n_in_use + 1; // end-of-block symbol index

        // MTF alphabet: yy[rank] = the actual byte value for that rank.
        // Initialised from seq_to_unseq which maps compact MTF indices to bytes.
        let mut yy = [0u8; 256];
        yy[..self.n_in_use].copy_from_slice(&self.seq_to_unseq[..self.n_in_use]);

        self.unzftab = [0; 256];
        let mut last: i32 = -1; // index of the last byte written into tt[]

        // Huffman decode state — shared between the outer loop and the
        // RUNA/RUNB inner loop via the get_next_sym! macro below.
        let mut group_no: i32 = -1;
        let mut group_pos: i32 = 0;
        let mut zt: usize = 0;
        let mut zn: i32; // always assigned inside get_next_sym! before use
        let mut zvec: i32; // always assigned inside get_next_sym! before use

        // Fetch the next Huffman symbol.
        // Advances group_no / group_pos when the current G_SIZE group is used up,
        // then reads enough bits to decode one symbol from the selected table.
        macro_rules! get_next_sym {
            () => {{
                if group_pos == 0 {
                    group_no += 1;
                    group_pos = G_SIZE as i32;
                    zt = self.selector[group_no as usize] as usize;
                }
                group_pos -= 1;

                zn = self.min_lens[zt];
                zvec = self.bs_get_bits(zn)?;
                while zvec > self.limit[zt][zn as usize] {
                    zn += 1;
                    zvec = (zvec << 1) | self.bs_get_bit()?;
                }
                self.perm[zt][(zvec - self.base[zt][zn as usize]) as usize]
            }};
        }

        let mut next_sym = get_next_sym!();

        loop {
            if next_sym == eob as i32 {
                break;
            }

            if next_sym == RUNA as i32 || next_sym == RUNB as i32 {
                // Bijective base-2 run-length decode.
                // Each RUNA adds `n`, each RUNB adds `2*n`, then n doubles.
                // The run length is s+1 copies of yy[0].
                let mut s: i32 = -1;
                let mut n: i32 = 1;
                loop {
                    if next_sym == RUNA as i32 {
                        s += n;
                    } else {
                        s += 2 * n;
                    }
                    n <<= 1;
                    next_sym = get_next_sym!();
                    if next_sym != RUNA as i32 && next_sym != RUNB as i32 {
                        break;
                    }
                }
                s += 1;
                let ch = yy[0];
                self.unzftab[ch as usize] += s as usize;
                for _ in 0..s {
                    last += 1;
                    self.tt[last as usize] = ch as u32;
                }
                // next_sym already holds the symbol that ended the run;
                // continue the outer loop without fetching again.
            } else {
                // MTF decode: symbol value encodes the rank (1-based).
                last += 1;
                let rank = (next_sym - 1) as usize;
                let ch = yy[rank];
                // Move yy[rank] to the front: shift yy[0..rank] right by one.
                yy.copy_within(0..rank, 1);
                yy[0] = ch;
                self.unzftab[ch as usize] += 1;
                self.tt[last as usize] = ch as u32;
                next_sym = get_next_sym!();
            }
        }

        // Record the total number of bytes decoded in this block.
        self.count = (last + 1) as usize;
        Ok(())
    }

    /// Build the BWT inverse chain (`tt[]`) from `unzftab[]` and the raw
    /// block bytes, and position `t_pos` at `orig_ptr`.
    ///
    /// After this call the block is ready for the RLE output pass.
    ///
    /// # Combined encoding of `tt[]`
    ///
    /// After this function returns, each entry encodes two values:
    ///
    /// ```text
    ///  tt[j]  =  (byte_at_j << 24)  |  chain_j
    ///             ───────────────────   ────────
    ///             bits 31–24            bits 23–0
    ///             BWT last-column       chain pointer: the BWT source
    ///             byte at position j    position that sorts to rank j
    /// ```
    ///
    /// The output loop in `setup_rand_part_a` uses:
    /// ```text
    ///  ch     = (tt[t_pos] >> 24) as u8
    ///  t_pos  = (tt[t_pos] & 0x00_FF_FF_FF) as usize
    /// ```
    fn setup_block(&mut self) {
        // tt[i] currently holds only the raw BWT byte in the low 8 bits
        // (written by get_and_move_to_front_decode).  We need those bytes
        // both as ll8[i] (to build the chain) and as ll8[j] (to pack into
        // the high 8 bits at the chain destination j).  A temporary copy
        // lets us read either without fighting the borrow checker.
        let ll8: Vec<u8> = self.tt[..self.count].iter().map(|&v| v as u8).collect();

        // cftab[b] = number of bytes with value < b (prefix sum of unzftab).
        // cftab[b] is the starting sorted rank for byte value b, and is
        // incremented as each source position is assigned a rank.
        let mut cftab = [0usize; 257];
        cftab[1..257].copy_from_slice(&self.unzftab);
        for i in 1..=256 {
            cftab[i] += cftab[i - 1];
        }

        // Build the combined BWT inverse chain.
        // For each source position i with byte value uc:
        //   j = next available sorted rank for uc  (= cftab[uc])
        //   tt[j] = (ll8[j] << 24) | i
        //             ^               ^
        //             byte at rank j  chain: rank j came from source i
        for i in 0..self.count {
            let uc = ll8[i] as usize;
            let j = cftab[uc];
            cftab[uc] += 1;
            self.tt[j] = ((ll8[j] as u32) << 24) | (i as u32);
        }

        // Advance the walking pointer once: start at the chain pointer
        // stored at orig_ptr (the low 24 bits), not at orig_ptr itself.
        self.t_pos = (self.tt[self.orig_ptr] & 0x00_FF_FF_FF) as usize;

        // Reset per-block output counters.
        self.t_i = 0;
        self.j2 = 0;
        self.current_char = -1; // no byte pending (equivalent to ch2 = 256 in C#)
    }

    /// Verify the block CRC against `stored_block_crc` and fold it into
    /// `computed_stream_crc`.  Returns an error on mismatch.
    fn end_block(&mut self) -> io::Result<()> {
        let block_final_crc = self.block_crc.get_final();
        if block_final_crc != self.stored_block_crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bzip2: block CRC mismatch",
            ));
        }
        // Same accumulation formula used by BZip2Writer::end_block.
        self.computed_stream_crc = self.computed_stream_crc.rotate_left(1) ^ block_final_crc;
        Ok(())
    }

    /// Verify the stream CRC at EOS and mark the stream as finished.
    fn end_stream(&mut self) -> io::Result<()> {
        if self.computed_stream_crc != self.stored_stream_crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bzip2: stream CRC mismatch",
            ));
        }
        self.stream_end = true;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // RLE output state machine
    // -----------------------------------------------------------------------

    /// State A — fetch the next BWT character, begin a new RLE run.
    ///
    /// Advances `t_pos` through `tt[]`, applies randomisation if needed,
    /// stores the character in `t_ch`, and transitions to `RandPartB`.
    /// When the block is exhausted, calls `end_block` and transitions to
    /// `StartBlock` (or `NoProcess` if this was the last block).
    fn setup_rand_part_a(&mut self) -> io::Result<()> {
        if self.t_i >= self.count {
            self.end_block()?;
            self.current_state = ReaderState::StartBlock;
            return Ok(());
        }

        // Save previous character for run detection in state B.
        self.ch_prev = self.t_ch;

        // Advance the BWT walking pointer and extract the byte.
        //   tt[t_pos] = (byte_at_t_pos << 24) | next_t_pos
        let combined = self.tt[self.t_pos];
        self.t_ch = (combined >> 24) as u8;
        self.t_pos = (combined & 0x00_FF_FF_FF) as usize;

        // De-randomise: apply the same flip pattern the writer used.
        // r_n_to_go starts at 0; when it hits 0, reload from RNUMS[r_t_pos]
        // and advance r_t_pos.  After decrementing, XOR bit 0 when r_n_to_go == 1.
        if self.block_randomised {
            if self.r_n_to_go == 0 {
                self.r_n_to_go = RNUMS[self.r_t_pos] as i32;
                self.r_t_pos = (self.r_t_pos + 1) & 0x1FF;
            }
            self.r_n_to_go -= 1;
            if self.r_n_to_go == 1 {
                self.t_ch ^= 1;
            }
        }

        self.t_i += 1;
        self.current_state = ReaderState::RandPartB;
        Ok(())
    }

    /// State B — accumulate an RLE run.
    ///
    /// While successive characters equal `ch_prev`, increments `j2`.
    /// At `j2 == 4` the fifth character is the repeat count; transitions
    /// to `RandPartC`.  Otherwise sets `current_char` / `output_count`
    /// and transitions back to `RandPartA`.
    fn setup_rand_part_b(&mut self) -> io::Result<()> {
        if self.j2 == 4 {
            // t_ch is the repeat-count byte (the byte A just read after seeing
            // four identical characters).  It is a control byte — not emitted
            // as data and not counted in the CRC.
            self.z = self.t_ch as i32;
            self.j2 = 0;
            self.current_state = if self.z > 0 {
                ReaderState::RandPartC
            } else {
                ReaderState::RandPartA
            };
        } else if self.t_ch == self.ch_prev && self.j2 > 0 {
            // Same character as the previous one: extend the run.
            self.j2 += 1;
            self.block_crc.update(self.t_ch);
            self.current_char = self.t_ch as i32;
            self.output_count = 1;
            self.current_state = ReaderState::RandPartA;
        } else {
            // New character (or first character of the block: j2 == 0).
            // Begin a fresh run of length 1.
            self.j2 = 1;
            self.block_crc.update(self.t_ch);
            self.current_char = self.t_ch as i32;
            self.output_count = 1;
            self.current_state = ReaderState::RandPartA;
        }
        Ok(())
    }

    /// State C — emit the run extension.
    ///
    /// Decrements `z`; when exhausted transitions back to `RandPartA`.
    /// Sets `current_char` / `output_count` for the repeated byte.
    fn setup_rand_part_c(&mut self) -> io::Result<()> {
        self.block_crc.update(self.ch_prev);
        self.current_char = self.ch_prev as i32;
        self.output_count = 1;
        self.z -= 1;
        if self.z == 0 {
            self.current_state = ReaderState::RandPartA;
        }
        Ok(())
    }
}

impl<R: Read> Read for BZip2Reader<R> {
    /// Decompress bytes into `buf`, returning the number of bytes written.
    ///
    /// Returns `Ok(0)` at end-of-stream.
    ///
    /// # Internal flow
    ///
    /// ```text
    /// while buf has space:
    ///     drain pending output_count for current_char
    ///     advance state machine → produces next current_char + output_count
    ///         StartBlock  → init_block()
    ///         RandPartA   → setup_rand_part_a()
    ///         RandPartB   → setup_rand_part_b()
    ///         RandPartC   → setup_rand_part_c()
    ///         NoProcess   → stop (EOF)
    /// ```
    /// 變動時間：依資料內容分支，只能用於公開值。
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut written = 0;

        'fill: while written < buf.len() {
            // Drain pending copies of current_char first.
            while self.output_count > 0 {
                if written >= buf.len() {
                    break 'fill;
                }
                buf[written] = self.current_char as u8;
                written += 1;
                self.output_count -= 1;
            }

            // Advance the state machine to produce the next character.
            match self.current_state {
                ReaderState::StartBlock => self.init_block()?,
                ReaderState::RandPartA => self.setup_rand_part_a()?,
                ReaderState::RandPartB => self.setup_rand_part_b()?,
                ReaderState::RandPartC => self.setup_rand_part_c()?,
                ReaderState::NoProcess => break 'fill,
            }
        }

        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::super::bzip2_writer::BZip2Writer;
    use super::BZip2Reader;

    /// Compress `data` with BZip2Writer at the given block size, then return
    /// the raw compressed bytes.
    fn compress(data: &[u8], block_size: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = BZip2Writer::with_block_size(&mut buf, block_size).unwrap();
            w.write_all(data).unwrap();
            w.finish().unwrap();
        } // drop w, releasing the borrow on buf
        buf
    }

    /// Decompress a bzip2 byte slice and return the original bytes.
    fn decompress(compressed: &[u8]) -> Vec<u8> {
        let mut r = BZip2Reader::new(compressed).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        out
    }

    /// Round-trip `data` and assert it survives unchanged.
    fn round_trip(data: &[u8], block_size: usize) {
        let compressed = compress(data, block_size);
        let got = decompress(&compressed);
        assert_eq!(got, data, "round-trip failed for {} bytes", data.len());
    }

    // --- basic cases ---

    #[test]
    fn empty_input() {
        round_trip(b"", 9);
    }

    #[test]
    fn single_byte() {
        round_trip(b"A", 9);
    }

    #[test]
    fn short_ascii() {
        round_trip(b"Hello, world!", 9);
    }

    #[test]
    fn all_byte_values() {
        let data: Vec<u8> = (0u8..=255).collect();
        round_trip(&data, 9);
    }

    // --- RLE corner cases ---

    /// Exactly 4 identical bytes: triggers the run-length path with count = 0
    /// (no extra copies beyond the 4).
    #[test]
    fn run_of_exactly_4() {
        round_trip(&[0xA5u8; 4], 9);
    }

    /// 5 identical bytes: count byte = 1 (one extra beyond 4).
    #[test]
    fn run_of_5() {
        round_trip(&[0xA5u8; 5], 9);
    }

    /// 259 identical bytes: count byte = 255 (maximum extra copies beyond 4).
    #[test]
    fn run_of_259() {
        round_trip(&[0xFFu8; 259], 9);
    }

    /// Two back-to-back runs of 4+ identical bytes with a different byte between
    /// them, exercising the run-counter reset path.
    #[test]
    fn two_runs_separated() {
        let mut data = vec![b'A'; 8];
        data.push(b'B');
        data.extend_from_slice(&[b'C'; 8]);
        round_trip(&data, 9);
    }

    // --- block size variants ---

    #[test]
    fn block_size_1() {
        round_trip(b"block size one test", 1);
    }

    #[test]
    fn block_size_9() {
        round_trip(b"block size nine test", 9);
    }

    /// Data larger than a single block at block_size=1 (100 000 bytes), forcing
    /// the reader through multiple block boundaries.
    #[test]
    fn multi_block() {
        let data: Vec<u8> = (0u8..=255).cycle().take(120_000).collect();
        round_trip(&data, 1);
    }

    // --- small-buffer reads ---

    /// Read decompressed output one byte at a time to exercise the
    /// `output_count` drain loop in every possible state.
    #[test]
    fn read_one_byte_at_a_time() {
        let data = b"one byte at a time";
        let compressed = compress(data, 9);
        let mut r = BZip2Reader::new(compressed.as_slice()).unwrap();
        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = r.read(&mut byte).unwrap();
            if n == 0 {
                break;
            }
            out.push(byte[0]);
        }
        assert_eq!(out, data);
    }

    // --- error cases ---

    #[test]
    fn bad_magic_returns_error() {
        match BZip2Reader::new(b"notbzip2data".as_ref()) {
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
            Ok(_) => panic!("expected an error for invalid magic"),
        }
    }

    #[test]
    fn truncated_stream_returns_error() {
        let compressed = compress(b"some data", 9);
        // Feed only the first half of the compressed stream.
        let half = &compressed[..compressed.len() / 2];
        let mut r = BZip2Reader::new(half).unwrap();
        let result = r.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }
}
