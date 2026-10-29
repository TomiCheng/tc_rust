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

//! BZip2 compression writer.
//!
//! Port of `CBZip2OutputStream.cs` from bc-csharp.

use std::io::{self, Write};

use super::constants::*;
use super::crc::Crc;

/// Random number table used to randomize blocks that fail to sort efficiently.
/// Shared with [`super::bzip2_reader`] (equivalent to C#'s `internal static`).
pub(super) const RNUMS: [u16; 512] = [
    619, 720, 127, 481, 931, 816, 813, 233, 566, 247, 985, 724, 205, 454, 863, 491, 741, 242, 949,
    214, 733, 859, 335, 708, 621, 574, 73, 654, 730, 472, 419, 436, 278, 496, 867, 210, 399, 680,
    480, 51, 878, 465, 811, 169, 869, 675, 611, 697, 867, 561, 862, 687, 507, 283, 482, 129, 807,
    591, 733, 623, 150, 238, 59, 379, 684, 877, 625, 169, 643, 105, 170, 607, 520, 932, 727, 476,
    693, 425, 174, 647, 73, 122, 335, 530, 442, 853, 695, 249, 445, 515, 909, 545, 703, 919, 874,
    474, 882, 500, 594, 612, 641, 801, 220, 162, 819, 984, 589, 513, 495, 799, 161, 604, 958, 533,
    221, 400, 386, 867, 600, 782, 382, 596, 414, 171, 516, 375, 682, 485, 911, 276, 98, 553, 163,
    354, 666, 933, 424, 341, 533, 870, 227, 730, 475, 186, 263, 647, 537, 686, 600, 224, 469, 68,
    770, 919, 190, 373, 294, 822, 808, 206, 184, 943, 795, 384, 383, 461, 404, 758, 839, 887, 715,
    67, 618, 276, 204, 918, 873, 777, 604, 560, 951, 160, 578, 722, 79, 804, 96, 409, 713, 940,
    652, 934, 970, 447, 318, 353, 859, 672, 112, 785, 645, 863, 803, 350, 139, 93, 354, 99, 820,
    908, 609, 772, 154, 274, 580, 184, 79, 626, 630, 742, 653, 282, 762, 623, 680, 81, 927, 626,
    789, 125, 411, 521, 938, 300, 821, 78, 343, 175, 128, 250, 170, 774, 972, 275, 999, 639, 495,
    78, 352, 126, 857, 956, 358, 619, 580, 124, 737, 594, 701, 612, 669, 112, 134, 694, 363, 992,
    809, 743, 168, 974, 944, 375, 748, 52, 600, 747, 642, 182, 862, 81, 344, 805, 988, 739, 511,
    655, 814, 334, 249, 515, 897, 955, 664, 981, 649, 113, 974, 459, 893, 228, 433, 837, 553, 268,
    926, 240, 102, 654, 459, 51, 686, 754, 806, 760, 493, 403, 415, 394, 687, 700, 946, 670, 656,
    610, 738, 392, 760, 799, 887, 653, 978, 321, 576, 617, 626, 502, 894, 679, 243, 440, 680, 879,
    194, 572, 640, 724, 926, 56, 204, 700, 707, 151, 457, 449, 797, 195, 791, 558, 945, 679, 297,
    59, 87, 824, 713, 663, 412, 693, 342, 606, 134, 108, 571, 364, 631, 212, 174, 643, 304, 329,
    343, 97, 430, 751, 497, 314, 983, 374, 822, 928, 140, 206, 73, 263, 980, 736, 876, 478, 430,
    305, 170, 514, 364, 692, 829, 82, 855, 953, 676, 246, 369, 970, 294, 750, 807, 827, 150, 790,
    288, 923, 804, 378, 215, 828, 592, 281, 565, 555, 710, 82, 896, 831, 547, 261, 524, 462, 293,
    465, 502, 56, 661, 821, 976, 991, 658, 869, 905, 758, 745, 193, 768, 550, 608, 933, 378, 286,
    215, 979, 792, 961, 61, 688, 793, 644, 986, 403, 106, 366, 905, 644, 372, 567, 466, 434, 645,
    210, 389, 550, 919, 135, 780, 773, 635, 389, 707, 100, 626, 958, 165, 504, 920, 176, 193, 713,
    857, 265, 203, 50, 668, 108, 645, 990, 626, 197, 510, 357, 358, 850, 858, 364, 936, 638,
];

/// Shell sort increment sequence (Knuth's increments).
const INCS: [i32; 14] = [
    1, 4, 13, 40, 121, 364, 1093, 3280, 9841, 29524, 88573, 265720, 797161, 2391484,
];

const SET_MARK: i32 = 1 << 21;
const CLEAR_MASK: i32 = !SET_MARK;
const GREATER_ICOST: u8 = 15;
const LESSER_ICOST: u8 = 0;
const SMALL_THRESH: i32 = 20;
const DEPTH_THRESH: i32 = 10;

/// BZip2 compression writer.
///
/// Wraps an inner [`Write`] and compresses data into the bzip2 format.
/// Call [`BZip2Writer::finish`] when done to flush all remaining data and
/// write the end-of-stream marker. Dropping without calling `finish` will
/// attempt a best-effort flush but any I/O errors will be silently ignored.
pub struct BZip2Writer<W: Write> {
    inner: W,
    finished: bool,

    // --- Block state ---
    /// Number of bytes currently in the block (1-based index into block_bytes).
    count: usize,
    /// Index in zptr[] of the original string after BWT sorting.
    orig_ptr: usize,
    /// Maximum count before the block must be flushed (block size - 20 bytes safety margin).
    allowable_block_size: usize,
    /// Whether the current block was randomised (to avoid worst-case sort behaviour).
    block_randomised: bool,

    // --- Bit output buffer ---
    /// Accumulated bits waiting to be written; MSB is written first.
    bs_buff: i32,
    /// Number of free bit positions remaining in bs_buff (counts down from 32).
    bs_live_pos: i32,

    // --- CRC ---
    block_crc: Crc,
    stream_crc: u32,

    // --- Symbol / alphabet tracking ---
    /// Which byte values appear in the current block.
    in_use: [bool; 256],
    /// Number of distinct byte values in use.
    n_in_use: usize,

    // --- Huffman selectors ---
    /// Which Huffman table to use for each G_SIZE-symbol group.
    selectors: Vec<u8>, // MAX_SELECTORS entries

    // --- Block buffers (allocated once based on block_size_100k) ---
    /// Input block data (1-based; index 0 is a sentinel copy of the last byte).
    block_bytes: Vec<u8>, // n + 1 + NUM_OVERSHOOT_BYTES
    /// Quadrant values used to break ties during BWT suffix comparison.
    quadrant_shorts: Vec<u16>, // n + 1 + NUM_OVERSHOOT_BYTES
    /// Suffix-array permutation produced by block sorting.
    /// Also reused as szptr (MTF output) since szptr values fit in i32.
    zptr: Vec<i32>, // n entries
    /// Frequency table for radix sort (65537 entries).
    ftab: Vec<i32>,

    // --- MTF (Move-To-Front) state ---
    /// Total number of MTF-encoded symbols written.
    n_mtf: usize,
    /// Per-symbol frequency counts after MTF transform.
    mtf_freq: Vec<i32>, // MAX_ALPHA_SIZE entries

    // --- Block sorting control ---
    work_factor: i32,
    work_done: i32,
    work_limit: i32,
    first_attempt: bool,
    /// Explicit stack for QSort3 to avoid system stack overflow on deep recursion.
    block_sort_stack: Vec<(i32, i32, i32)>, // (ll, hh, dd)

    // --- RLE input state ---
    /// The byte value currently being accumulated, or None if no run is active.
    current_byte: Option<u8>,
    /// Length of the current run.
    run_length: usize,
}

impl<W: Write> BZip2Writer<W> {
    /// Create a new BZip2 writer with compression level 9 (maximum).
    /// 變動時間：依資料內容分支，只能用於公開值。
    pub fn new(inner: W) -> io::Result<Self> {
        Self::with_block_size(inner, 9)
    }

    /// Create a new BZip2 writer with a given block size (1–9).
    /// Higher values give better compression at the cost of more memory.
    /// 變動時間：依資料內容分支，只能用於公開值。
    pub fn with_block_size(mut inner: W, block_size: usize) -> io::Result<Self> {
        let block_size_100k = block_size.clamp(1, 9);
        let n = BASE_BLOCK_SIZE * block_size_100k;
        let allowable_block_size = n - 20;

        // Write stream header: "BZh" + block size digit
        inner.write_all(&[b'B', b'Z', b'h', b'0' + block_size_100k as u8])?;

        let mut writer = Self {
            inner,
            finished: false,
            count: 0,
            orig_ptr: 0,
            allowable_block_size,
            block_randomised: false,
            bs_buff: 0,
            bs_live_pos: 32,
            block_crc: Crc::new(),
            stream_crc: 0,
            in_use: [false; 256],
            n_in_use: 0,
            selectors: vec![0u8; MAX_SELECTORS],
            block_bytes: vec![0u8; n + 1 + NUM_OVERSHOOT_BYTES],
            quadrant_shorts: vec![0u16; n + 1 + NUM_OVERSHOOT_BYTES],
            zptr: vec![0i32; n],
            ftab: vec![0i32; 65537],
            n_mtf: 0,
            mtf_freq: vec![0i32; MAX_ALPHA_SIZE],
            work_factor: 50,
            work_done: 0,
            work_limit: 0,
            first_attempt: false,
            block_sort_stack: Vec::new(),
            current_byte: None,
            run_length: 0,
        };

        writer.init_block();
        Ok(writer)
    }
}

impl<W: Write> BZip2Writer<W> {
    fn init_block(&mut self) {
        self.block_crc.initialise();
        self.count = 0;
        self.in_use = [false; 256];
    }

    /// Flush all remaining data and write the end-of-stream marker.
    ///
    /// Must be called explicitly to ensure the compressed output is complete.
    /// Dropping the writer will attempt this automatically, but any I/O errors
    /// will be silently ignored.
    /// 變動時間：依資料內容分支，只能用於公開值。
    pub fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        if self.run_length > 0 {
            self.write_run()?;
        }
        self.current_byte = None;
        if self.count > 0 {
            self.end_block()?;
        }
        self.end_compression()?;
        self.finished = true;
        self.inner.flush()
    }

    fn write_byte_internal(&mut self, value: u8) -> io::Result<()> {
        if self.current_byte == Some(value) {
            self.run_length += 1;
            if self.run_length > 254 {
                self.write_run()?;
                self.current_byte = None;
                self.run_length = 0;
            }
        } else {
            if self.current_byte.is_some() {
                self.write_run()?;
            }
            self.current_byte = Some(value);
            self.run_length = 1;
        }
        Ok(())
    }

    fn write_run(&mut self) -> io::Result<()> {
        if self.count > self.allowable_block_size {
            self.end_block()?;
            self.init_block();
        }

        let ch = self
            .current_byte
            .expect("write_run called with no current byte");
        self.in_use[ch as usize] = true;

        match self.run_length {
            1 => {
                self.count += 1;
                self.block_bytes[self.count] = ch;
                self.block_crc.update(ch);
            }
            2 => {
                self.count += 1;
                self.block_bytes[self.count] = ch;
                self.count += 1;
                self.block_bytes[self.count] = ch;
                self.block_crc.update(ch);
                self.block_crc.update(ch);
            }
            3 => {
                self.count += 1;
                self.block_bytes[self.count] = ch;
                self.count += 1;
                self.block_bytes[self.count] = ch;
                self.count += 1;
                self.block_bytes[self.count] = ch;
                self.block_crc.update(ch);
                self.block_crc.update(ch);
                self.block_crc.update(ch);
            }
            run_length => {
                let repeat = run_length - 4;
                self.count += 1;
                self.block_bytes[self.count] = ch;
                self.count += 1;
                self.block_bytes[self.count] = ch;
                self.count += 1;
                self.block_bytes[self.count] = ch;
                self.count += 1;
                self.block_bytes[self.count] = ch;
                self.count += 1;
                self.block_bytes[self.count] = repeat as u8;
                self.in_use[repeat] = true;
                self.block_crc.update_run(ch, run_length);
            }
        }

        Ok(())
    }

    fn end_block(&mut self) -> io::Result<()> {
        let block_final_crc = self.block_crc.get_final();
        self.stream_crc = self.stream_crc.rotate_left(1) ^ block_final_crc;

        self.do_reversible_transformation()?;

        // 48-bit block header magic: 0x314159265359 (pi)
        self.bs_put_long48(0x314159265359u64)?;
        self.bs_put_int32(block_final_crc)?;
        self.bs_put_bit(if self.block_randomised { 1 } else { 0 })?;

        self.move_to_front_code_and_send()
    }

    fn do_reversible_transformation(&mut self) -> io::Result<()> {
        self.work_limit = self.work_factor * (self.count as i32 - 1);
        self.work_done = 0;
        self.block_randomised = false;
        self.first_attempt = true;

        self.main_sort();

        if self.work_done > self.work_limit && self.first_attempt {
            self.randomise_block();
            self.work_limit = 0;
            self.work_done = 0;
            self.block_randomised = true;
            self.first_attempt = false;
            self.main_sort();
        }

        // Find the position of the original string in the sorted order (origPtr).
        self.orig_ptr = (0..self.count)
            .find(|&i| self.zptr[i] == 0)
            .ok_or_else(|| io::Error::other("BWT: original string not found after sorting"))?;

        Ok(())
    }

    fn main_sort(&mut self) {
        let count = self.count;

        // Set up overshoot area: copy first NUM_OVERSHOOT_BYTES bytes to end of block.
        for i in 0..NUM_OVERSHOOT_BYTES {
            self.block_bytes[count + i + 1] = self.block_bytes[(i % count) + 1];
        }
        for i in 0..=(count + NUM_OVERSHOOT_BYTES) {
            self.quadrant_shorts[i] = 0;
        }
        // Sentinel: index 0 mirrors the last byte so comparisons wrap correctly.
        self.block_bytes[0] = self.block_bytes[count];

        if count <= 4000 {
            self.main_sort_small();
        } else {
            self.main_sort_large();
        }
    }

    /// Sort small blocks (count <= 4000) using Shell sort.
    /// Lower constant overhead makes it faster than the full radix+QSort3 pipeline.
    fn main_sort_small(&mut self) {
        let count = self.count;
        for i in 0..count {
            self.zptr[i] = i as i32;
        }
        self.first_attempt = false;
        self.work_done = 0;
        self.work_limit = 0;
        self.simple_sort(0, count as i32 - 1, 0);
    }

    /// Sort large blocks (count > 4000) using radix sort + QSort3.
    fn main_sort_large(&mut self) {
        let running_order = self.main_sort_radix();
        self.main_sort_bucket_loop(running_order);
    }

    /// Radix sort phase: build 2-gram frequency table, place suffixes into
    /// initial bucket positions, then sort buckets by size (smallest first).
    /// Returns the running order array for use in the bucket loop.
    fn main_sort_radix(&mut self) -> [i32; 256] {
        let count = self.count;

        // Build 2-gram frequency table.
        self.ftab.fill(0);
        let mut c1 = self.block_bytes[0] as usize;
        for i in 1..=count {
            let c2 = self.block_bytes[i] as usize;
            self.ftab[(c1 << 8) + c2] += 1;
            c1 = c2;
        }

        // Prefix-sum to get bucket start positions.
        for i in 0..65536 {
            self.ftab[i + 1] += self.ftab[i];
        }

        // Place each suffix into its initial bucket position.
        c1 = self.block_bytes[1] as usize;
        for i in 0..(count - 1) {
            let c2 = self.block_bytes[i + 2] as usize;
            let j = (c1 << 8) + c2;
            c1 = c2;
            self.ftab[j] -= 1;
            self.zptr[self.ftab[j] as usize] = i as i32;
        }
        let j = (self.block_bytes[count] as usize) << 8 | self.block_bytes[1] as usize;
        self.ftab[j] -= 1;
        self.zptr[self.ftab[j] as usize] = count as i32 - 1;

        // Sort big buckets by size (smallest first) using Shell sort.
        let mut running_order = [0i32; 256];
        for (i, r) in running_order.iter_mut().enumerate() {
            *r = i as i32;
        }
        let mut h = 1i32;
        while h <= 256 {
            h = 3 * h + 1;
        }
        loop {
            h /= 3;
            for i in h as usize..256 {
                let vv = running_order[i];
                let mut j = i;
                while self.ftab[((running_order[j - h as usize] + 1) as usize) << 8]
                    - self.ftab[(running_order[j - h as usize] as usize) << 8]
                    > self.ftab[((vv + 1) as usize) << 8] - self.ftab[(vv as usize) << 8]
                {
                    running_order[j] = running_order[j - h as usize];
                    j -= h as usize;
                    if j < h as usize {
                        break;
                    }
                }
                running_order[j] = vv;
            }
            if h == 1 {
                break;
            }
        }

        running_order
    }

    /// Bucket loop phase: QSort3 each small bucket, update quadrant values,
    /// and synthesise sorted order for cross-bucket entries.
    fn main_sort_bucket_loop(&mut self, running_order: [i32; 256]) {
        let count = self.count;
        let mut copy = [0i32; 256];
        let mut big_done = [false; 256];

        for (i, &ss_i) in running_order.iter().enumerate() {
            let ss = ss_i as usize;

            // QSort3 any unsorted small buckets [ss, j].
            for j in 0..256usize {
                let sb = (ss << 8) + j;
                if (self.ftab[sb] & SET_MARK) != SET_MARK {
                    let lo = self.ftab[sb] & CLEAR_MASK;
                    let hi = (self.ftab[sb + 1] & CLEAR_MASK) - 1;
                    if hi > lo {
                        self.q_sort3(lo, hi, 2);
                        if self.work_done > self.work_limit && self.first_attempt {
                            return;
                        }
                    }
                    self.ftab[sb] |= SET_MARK;
                }
            }

            big_done[ss] = true;

            // Update quadrant values for the completed big bucket.
            if i < 255 {
                let bb_start = (self.ftab[ss << 8] & CLEAR_MASK) as usize;
                let bb_size = (self.ftab[(ss + 1) << 8] & CLEAR_MASK) as usize - bb_start;

                let mut shifts = 0u32;
                while (bb_size >> shifts) > 65534 {
                    shifts += 1;
                }
                for j in 0..bb_size {
                    let a2update = self.zptr[bb_start + j] as usize + 1;
                    let q_val = (j >> shifts) as u16;
                    self.quadrant_shorts[a2update] = q_val;
                    if a2update <= NUM_OVERSHOOT_BYTES {
                        self.quadrant_shorts[a2update + count] = q_val;
                    }
                }
                debug_assert!(((bb_size.saturating_sub(1)) >> shifts) <= 65535);
            }

            // Synthesise sorted order for small buckets [t, ss] for all t != ss.
            for (j, c) in copy.iter_mut().enumerate() {
                *c = self.ftab[(j << 8) + ss] & CLEAR_MASK;
            }
            for j in (self.ftab[ss << 8] & CLEAR_MASK) as usize
                ..(self.ftab[(ss + 1) << 8] & CLEAR_MASK) as usize
            {
                let zptr_j = self.zptr[j] as usize;
                let c1 = self.block_bytes[zptr_j] as usize;
                if !big_done[c1] {
                    self.zptr[copy[c1] as usize] =
                        (if zptr_j == 0 { count } else { zptr_j }) as i32 - 1;
                    copy[c1] += 1;
                }
            }
            for j in 0..256usize {
                self.ftab[(j << 8) + ss] |= SET_MARK;
            }
        }
    }

    /// Shell sort on `zptr[lo..=hi]`, comparing suffixes starting at depth `d`.
    ///
    /// Used for small sub-ranges (≤ [`SMALL_THRESH`]) and when [`q_sort3`]
    /// exceeds [`DEPTH_THRESH`] recursion depth. Three elements are processed
    /// per outer iteration (loop unrolling) to reduce branch overhead.
    fn simple_sort(&mut self, lo: i32, hi: i32, d: i32) {
        let big_n = hi - lo + 1;
        if big_n < 2 {
            return;
        }

        // Find the largest Shell sort increment smaller than big_n.
        // partition_point returns the first index where INCS[i] >= big_n.
        // Since big_n >= 2 > INCS[0]=1, the result is always >= 1.
        let hp = INCS.partition_point(|&inc| inc < big_n) as i32 - 1;

        // Outer loop: shrink the increment from largest to 1 (standard Shell sort).
        let mut hp = hp;
        while hp >= 0 {
            let h = INCS[hp as usize];

            // Inner loop: insertion sort with gap h.
            // Processes 3 elements per iteration to reduce loop-control overhead.
            let mut i = lo + h;
            while i <= hi {
                // --- element 1 ---
                // Save the suffix index to insert, then shift elements right
                // until we find the correct position.
                let v = self.zptr[i as usize];
                let mut j = i;
                loop {
                    // Read zptr[j-h] before calling full_gt_u (borrow checker:
                    // cannot hold &self.zptr reference across a &mut self call).
                    let zptr_jh = self.zptr[(j - h) as usize];
                    if !self.full_gt_u(zptr_jh + d, v + d) {
                        break;
                    }
                    self.zptr[j as usize] = zptr_jh;
                    j -= h;
                    if j < lo + h {
                        break;
                    }
                }
                self.zptr[j as usize] = v;

                // --- element 2 ---
                i += 1;
                if i > hi {
                    break;
                }
                let v = self.zptr[i as usize];
                let mut j = i;
                loop {
                    let zptr_jh = self.zptr[(j - h) as usize];
                    if !self.full_gt_u(zptr_jh + d, v + d) {
                        break;
                    }
                    self.zptr[j as usize] = zptr_jh;
                    j -= h;
                    if j < lo + h {
                        break;
                    }
                }
                self.zptr[j as usize] = v;

                // --- element 3 ---
                i += 1;
                if i > hi {
                    break;
                }
                let v = self.zptr[i as usize];
                let mut j = i;
                loop {
                    let zptr_jh = self.zptr[(j - h) as usize];
                    if !self.full_gt_u(zptr_jh + d, v + d) {
                        break;
                    }
                    self.zptr[j as usize] = zptr_jh;
                    j -= h;
                    if j < lo + h {
                        break;
                    }
                }
                self.zptr[j as usize] = v;
                i += 1;

                // Early exit if too much work done (block will be randomised and retried).
                if self.work_done > self.work_limit && self.first_attempt {
                    return;
                }
            }
            hp -= 1;
        }
    }

    /// Compare two suffixes starting at positions `i1+1` and `i2+1`.
    /// Returns `true` if suffix at `i1` is lexicographically greater than at `i2`.
    ///
    /// Two phases:
    /// - Fast path: compare the first 6 bytes directly (no quadrant lookup).
    /// - Slow path: compare 4 bytes per iteration, using `quadrant_shorts` to
    ///   break ties. Each slow-path iteration increments `work_done` so the
    ///   caller can detect worst-case inputs and bail out early.
    fn full_gt_u(&mut self, mut i1: i32, mut i2: i32) -> bool {
        // --- Fast path: first 6 bytes ---
        // Unrolled to avoid loop overhead for the common case.
        macro_rules! cmp_byte {
            () => {
                i1 += 1;
                i2 += 1;
                let c1 = self.block_bytes[i1 as usize];
                let c2 = self.block_bytes[i2 as usize];
                if c1 != c2 {
                    return c1 > c2;
                }
            };
        }
        cmp_byte!();
        cmp_byte!();
        cmp_byte!();
        cmp_byte!();
        cmp_byte!();
        cmp_byte!();

        // --- Slow path: 4 bytes + quadrant tiebreak per iteration ---
        // Processes the remaining suffix cyclically, wrapping around at `count`.
        let mut k = self.count as i32;
        loop {
            macro_rules! cmp_byte_quad {
                () => {
                    i1 += 1;
                    i2 += 1;
                    let c1 = self.block_bytes[i1 as usize];
                    let c2 = self.block_bytes[i2 as usize];
                    if c1 != c2 {
                        return c1 > c2;
                    }
                    let s1 = self.quadrant_shorts[i1 as usize];
                    let s2 = self.quadrant_shorts[i2 as usize];
                    if s1 != s2 {
                        return s1 > s2;
                    }
                };
            }
            cmp_byte_quad!();
            cmp_byte_quad!();
            cmp_byte_quad!();
            cmp_byte_quad!();

            // Wrap around for cyclic suffix comparison.
            let count = self.count as i32;
            if i1 >= count {
                i1 -= count;
            }
            if i2 >= count {
                i2 -= count;
            }

            k -= 4;
            self.work_done += 1;

            if k < 0 {
                break;
            }
        }

        // All bytes equal — suffixes are identical rotations, treat as not greater.
        false
    }

    /// Three-way quicksort on `zptr[lo..=hi]`, comparing suffixes at depth `d`.
    ///
    /// Uses an explicit stack (`blocksort_stack`) instead of recursion to avoid
    /// system stack overflow on pathological inputs. Falls back to [`simple_sort`]
    /// when the range is small or the depth exceeds [`DEPTH_THRESH`].
    fn q_sort3(&mut self, lo_st: i32, hi_st: i32, d_st: i32) {
        let mut lo = lo_st;
        let mut hi = hi_st;
        let mut d = d_st;

        loop {
            // Small range or deep recursion: delegate to Shell sort.
            if hi - lo < SMALL_THRESH || d > DEPTH_THRESH {
                self.simple_sort(lo, hi, d);
                if self.block_sort_stack.is_empty()
                    || (self.work_done > self.work_limit && self.first_attempt)
                {
                    return;
                }
                let (ll, hh, dd) = self.block_sort_stack.pop().unwrap();
                lo = ll;
                hi = hh;
                d = dd;
                continue;
            }

            let d1 = d + 1;

            // Pivot: median of three at positions lo, hi, and mid.
            let med = {
                let a = self.block_bytes[self.zptr[lo as usize] as usize + d1 as usize] as i32;
                let b = self.block_bytes[self.zptr[hi as usize] as usize + d1 as usize] as i32;
                let c = self.block_bytes
                    [self.zptr[((lo + hi) >> 1) as usize] as usize + d1 as usize]
                    as i32;
                Self::med3(a, b, c)
            };

            // Three-way partition (Dutch National Flag):
            //   zptr[lo..ltLo]   < med
            //   zptr[ltLo..unLo] = med
            //   zptr[unHi+1..gtHi+1] = med
            //   zptr[gtHi+1..=hi] > med
            let (mut un_lo, mut lt_lo) = (lo, lo);
            let (mut un_hi, mut gt_hi) = (hi, hi);

            'partition: loop {
                // Scan from left: skip elements equal to med (move to lt partition),
                // stop when element > med.
                while un_lo <= un_hi {
                    let z_un_lo = self.zptr[un_lo as usize];
                    let n = self.block_bytes[z_un_lo as usize + d1 as usize] as i32 - med;
                    if n > 0 {
                        break;
                    }
                    if n == 0 {
                        self.zptr[un_lo as usize] = self.zptr[lt_lo as usize];
                        self.zptr[lt_lo as usize] = z_un_lo;
                        lt_lo += 1;
                    }
                    un_lo += 1;
                }
                // Scan from right: skip elements equal to med (move to gt partition),
                // stop when element < med.
                while un_lo <= un_hi {
                    let z_un_hi = self.zptr[un_hi as usize];
                    let n = self.block_bytes[z_un_hi as usize + d1 as usize] as i32 - med;
                    if n < 0 {
                        break;
                    }
                    if n == 0 {
                        self.zptr[un_hi as usize] = self.zptr[gt_hi as usize];
                        self.zptr[gt_hi as usize] = z_un_hi;
                        gt_hi -= 1;
                    }
                    un_hi -= 1;
                }
                if un_lo > un_hi {
                    break 'partition;
                }
                // Swap the out-of-place elements.
                self.zptr.swap(un_lo as usize, un_hi as usize);
                un_lo += 1;
                un_hi -= 1;
            }

            // All elements equal to pivot: just go deeper.
            if gt_hi < lt_lo {
                d = d1;
                continue;
            }

            // Move the equal-to-pivot elements from the edges to the centre.
            let n = (lt_lo - lo).min(un_lo - lt_lo);
            self.vswap(lo, un_lo - n, n);

            let m = (hi - gt_hi).min(gt_hi - un_hi);
            self.vswap(un_lo, hi - m + 1, m);

            // Push the < and > sub-ranges onto the stack; handle = range next.
            let n = lo + (un_lo - lt_lo);
            let m = hi - (gt_hi - un_hi);

            self.block_sort_stack.push((lo, n - 1, d));
            self.block_sort_stack.push((n, m, d1));

            lo = m + 1;
        }
    }

    /// Swap `n` elements between `zptr[p1..]` and `zptr[p2..]`.
    fn vswap(&mut self, mut p1: i32, mut p2: i32, mut n: i32) {
        while n > 0 {
            self.zptr.swap(p1 as usize, p2 as usize);
            p1 += 1;
            p2 += 1;
            n -= 1;
        }
    }

    /// Median of three values — used for pivot selection in [`q_sort3`].
    fn med3(a: i32, b: i32, c: i32) -> i32 {
        if a > b {
            if c < b {
                b
            } else if c > a {
                a
            } else {
                c
            }
        } else {
            if c < a {
                a
            } else if c > b {
                b
            } else {
                c
            }
        }
    }

    /// Lightly randomise the block to break up repetitive patterns that cause
    /// worst-case sort behaviour. Called when the first [`main_sort`] attempt
    /// exceeds `work_limit`. The same [`RNUMS`] table is used by the decompressor
    /// to reverse the randomisation.
    fn randomise_block(&mut self) {
        // Reset in_use: randomisation may change which byte values are present.
        self.in_use = [false; 256];

        let mut r_n_to_go = 0i32;
        let mut r_t_pos = 0usize;

        for i in 1..=self.count {
            if r_n_to_go == 0 {
                r_n_to_go = RNUMS[r_t_pos] as i32;
                r_t_pos = (r_t_pos + 1) & 0x1FF; // wrap at 512
            }
            r_n_to_go -= 1;

            // XOR the byte with 1 exactly once per RNUMS cycle (when r_n_to_go == 1).
            self.block_bytes[i] ^= if r_n_to_go == 1 { 1 } else { 0 };

            self.in_use[self.block_bytes[i] as usize] = true;
        }
    }

    /// Write a single bit. Specialised form of [`bs_put_bits_small`] for n = 1.
    fn bs_put_bit(&mut self, v: i32) -> io::Result<()> {
        self.bs_put_bits_small(1, v)
    }

    /// Write `n` bits (1–24) of `v` into the bit buffer, flushing whole bytes
    /// to the inner writer as they fill up.
    ///
    /// The buffer (`bs_buff`) holds 32 bits. `bs_live_pos` counts down from 32
    /// indicating how many free positions remain. When `bs_live_pos <= 24` there
    /// are at least 8 ready bits; write the top byte and shift the buffer left.
    fn bs_put_bits(&mut self, n: i32, v: i32) -> io::Result<()> {
        debug_assert!((1..=24).contains(&n));
        self.bs_live_pos -= n;
        self.bs_buff |= v << self.bs_live_pos;
        while self.bs_live_pos <= 24 {
            self.inner.write_all(&[(self.bs_buff >> 24) as u8])?;
            self.bs_buff <<= 8;
            self.bs_live_pos += 8;
        }
        Ok(())
    }

    /// Write `n` bits (1–8) — single-flush variant of [`bs_put_bits`].
    /// Because n ≤ 8, at most one byte needs to be flushed per call.
    fn bs_put_bits_small(&mut self, n: i32, v: i32) -> io::Result<()> {
        debug_assert!((1..=8).contains(&n));
        self.bs_live_pos -= n;
        self.bs_buff |= v << self.bs_live_pos;
        if self.bs_live_pos <= 24 {
            self.inner.write_all(&[(self.bs_buff >> 24) as u8])?;
            self.bs_buff <<= 8;
            self.bs_live_pos += 8;
        }
        Ok(())
    }

    /// Write a 32-bit value as two 16-bit halves.
    fn bs_put_int32(&mut self, v: u32) -> io::Result<()> {
        self.bs_put_bits(16, ((v >> 16) & 0xFFFF) as i32)?;
        self.bs_put_bits(16, (v & 0xFFFF) as i32)
    }

    /// Write a 48-bit value as two 24-bit halves.
    fn bs_put_long48(&mut self, v: u64) -> io::Result<()> {
        self.bs_put_bits(24, ((v >> 24) & 0x00FF_FFFF) as i32)?;
        self.bs_put_bits(24, (v & 0x00FF_FFFF) as i32)
    }

    fn move_to_front_code_and_send(&mut self) -> io::Result<()> {
        // Write the BWT origin pointer so the decompressor knows which rotation
        // is the original string.
        self.bs_put_bits(24, self.orig_ptr as i32)?;
        self.generate_mtf_values();
        self.send_mtf_values()
    }

    /// Apply the Move-To-Front transform to the BWT output.
    ///
    /// Reads `block_bytes[zptr[i]]` for each sorted position, encodes it as
    /// the symbol's current rank in the MTF alphabet `yy`, then moves it to
    /// the front. Consecutive occurrences of rank 0 are batched into
    /// `RUNA`/`RUNB` symbols using a bijective base-2 encoding.
    /// Results are written into `zptr` (reused as `szptr`) and frequencies
    /// into `mtf_freq`.
    fn generate_mtf_values(&mut self) {
        // Build the initial MTF alphabet from in-use byte values.
        self.n_in_use = 0;
        let mut yy = [0u8; 256];
        for i in 0..256 {
            if self.in_use[i] {
                yy[self.n_in_use] = i as u8;
                self.n_in_use += 1;
            }
        }

        let eob = self.n_in_use + 1; // end-of-block symbol index

        // Clear frequency table for all symbols including EOB.
        for i in 0..=eob {
            self.mtf_freq[i] = 0;
        }

        let mut wr = 0usize; // write position in zptr (used as szptr)
        let mut z_pend = 0usize; // pending count of rank-0 occurrences

        for i in 0..self.count {
            let block_byte = self.block_bytes[self.zptr[i] as usize];

            // Fast path: byte matches the front of the alphabet (rank 0).
            if block_byte == yy[0] {
                z_pend += 1;
                continue;
            }

            // Flush any pending run of rank-0 symbols as RUNA/RUNB sequence.
            // Uses bijective base-2: repeatedly emit (z_pend-1) & 1 then shift.
            while z_pend > 0 {
                z_pend -= 1;
                let run = z_pend & 1; // RUNA = 0, RUNB = 1
                self.zptr[wr] = run as i32;
                wr += 1;
                self.mtf_freq[run] += 1;
                z_pend >>= 1;
            }

            // Find the byte's position in yy and move it to the front.
            let mut sym = 1usize;
            let mut tmp = yy[0];
            while block_byte != tmp {
                std::mem::swap(&mut tmp, &mut yy[sym]);
                sym += 1;
            }
            yy[0] = tmp;

            // Emit the rank symbol.
            self.zptr[wr] = sym as i32;
            wr += 1;
            self.mtf_freq[sym] += 1;
        }

        // Flush any remaining pending run.
        while z_pend > 0 {
            z_pend -= 1;
            let run = z_pend & 1;
            self.zptr[wr] = run as i32;
            wr += 1;
            self.mtf_freq[run] += 1;
            z_pend >>= 1;
        }

        // Emit the end-of-block symbol.
        self.zptr[wr] = eob as i32;
        wr += 1;
        self.mtf_freq[eob] += 1;

        self.n_mtf = wr;
    }

    fn send_mtf_values(&mut self) -> io::Result<()> {
        let alpha_size = self.n_in_use + 2;

        if self.n_mtf == 0 {
            return Err(io::Error::other("send_mtf_values: n_mtf is zero"));
        }

        // Choose number of Huffman tables based on MTF sequence length.
        let n_groups = match self.n_mtf {
            0..=199 => 2,
            200..=599 => 3,
            600..=1199 => 4,
            1200..=2399 => 5,
            _ => 6,
        };

        // Initialise code-length tables with GREATER_ICOST (15 = "don't use").
        let mut len = [[GREATER_ICOST; MAX_ALPHA_SIZE]; N_GROUPS];

        // Initial table assignment: divide the MTF sequence into nGroups
        // equal-frequency partitions and mark each partition's symbols as preferred.
        {
            let mut n_part = n_groups as i32;
            let mut rem_f = self.n_mtf as i32;
            let mut ge = -1i32;

            while n_part > 0 {
                let gs = ge + 1;
                let mut a_freq = 0i32;
                let t_freq = rem_f / n_part;

                while a_freq < t_freq && ge < alpha_size as i32 - 1 {
                    ge += 1;
                    a_freq += self.mtf_freq[ge as usize];
                }

                // Bias correction for odd-numbered partitions.
                if ge > gs
                    && n_part != n_groups as i32
                    && n_part != 1
                    && (n_groups as i32 - n_part) % 2 == 1
                {
                    a_freq -= self.mtf_freq[ge as usize];
                    ge -= 1;
                }

                let len_np = &mut len[(n_part - 1) as usize];
                for (v, l) in len_np.iter_mut().enumerate().take(alpha_size) {
                    *l = if v >= gs as usize && v <= ge as usize {
                        LESSER_ICOST
                    } else {
                        GREATER_ICOST
                    };
                }

                n_part -= 1;
                rem_f -= a_freq;
            }
        }

        // Iterative optimisation: N_ITERS rounds of (selector assignment →
        // frequency accumulation → code-length recomputation).
        let mut rfreq = [[0i32; MAX_ALPHA_SIZE]; N_GROUPS];
        let mut fave: [i32; N_GROUPS]; // initialised at the top of every iteration
        let mut cost = [0i16; N_GROUPS];
        let mut n_selectors = 0usize;

        for _iter in 0..N_ITERS {
            fave = [0i32; N_GROUPS];
            for rfreq_t in rfreq.iter_mut().take(n_groups) {
                rfreq_t[..alpha_size].fill(0);
            }

            n_selectors = 0;
            let mut gs = 0usize;

            while gs < self.n_mtf {
                let ge = (gs + G_SIZE - 1).min(self.n_mtf - 1);

                // Cost of encoding this G_SIZE group with each table.
                if n_groups == 6 {
                    let (mut c0, mut c1, mut c2, mut c3, mut c4, mut c5) =
                        (0i16, 0i16, 0i16, 0i16, 0i16, 0i16);
                    for i in gs..=ge {
                        let icv = self.zptr[i] as usize;
                        c0 += len[0][icv] as i16;
                        c1 += len[1][icv] as i16;
                        c2 += len[2][icv] as i16;
                        c3 += len[3][icv] as i16;
                        c4 += len[4][icv] as i16;
                        c5 += len[5][icv] as i16;
                    }
                    cost[0] = c0;
                    cost[1] = c1;
                    cost[2] = c2;
                    cost[3] = c3;
                    cost[4] = c4;
                    cost[5] = c5;
                } else {
                    cost[..n_groups].fill(0);
                    for i in gs..=ge {
                        let icv = self.zptr[i] as usize;
                        for t in 0..n_groups {
                            cost[t] += len[t][icv] as i16;
                        }
                    }
                }

                // Select cheapest table.
                let mut bc = cost[0] as i32;
                let mut bt = 0usize;
                for (t, &c) in cost.iter().enumerate().take(n_groups).skip(1) {
                    let ct = c as i32;
                    if ct < bc {
                        bc = ct;
                        bt = t;
                    }
                }
                fave[bt] += 1;
                self.selectors[n_selectors] = bt as u8;
                n_selectors += 1;

                for i in gs..=ge {
                    rfreq[bt][self.zptr[i] as usize] += 1;
                }

                gs = ge + 1;
            }

            // Rebuild code lengths from accumulated frequencies.
            for t in 0..n_groups {
                Self::hb_make_code_lengths(&mut len[t], &rfreq[t], alpha_size, MAX_CODE_LEN_GEN);
            }
        }

        debug_assert!(n_groups <= N_GROUPS);
        debug_assert!(n_selectors <= MAX_SELECTORS);

        // Assign canonical Huffman codes from the final code lengths.
        let mut code = [[0i32; MAX_ALPHA_SIZE]; N_GROUPS];
        for t in 0..n_groups {
            let mut max_len = 0i32;
            let mut min_len = 32i32;
            for &l in len[t].iter().take(alpha_size) {
                let lti = l as i32;
                max_len = max_len.max(lti);
                min_len = min_len.min(lti);
            }
            debug_assert!(min_len >= 1 && max_len <= MAX_CODE_LEN_GEN as i32);
            Self::hb_assign_codes(&mut code[t], &len[t], min_len, max_len, alpha_size);
        }

        // --- Output ---

        // Mapping table: which byte values appear in this block (16×16 bitmap).
        let mut in_use16 = [false; 16];
        for (i, flag) in in_use16.iter_mut().enumerate() {
            for j in 0..16usize {
                if self.in_use[i * 16 + j] {
                    *flag = true;
                    break;
                }
            }
        }
        for &flag in &in_use16 {
            self.bs_put_bit(flag as i32)?;
        }
        for (i, &flag) in in_use16.iter().enumerate() {
            if flag {
                for j in 0..16usize {
                    self.bs_put_bit(self.in_use[i * 16 + j] as i32)?;
                }
            }
        }

        // Selectors: 3-bit group count, 15-bit selector count, then each
        // selector encoded as its MTF rank in unary (rank-1 ones then a 0).
        // MTF ranks are 1-indexed (initial state 0x00654321 stores ranks 1–6).
        self.bs_put_bits_small(3, n_groups as i32)?;
        self.bs_put_bits(15, n_selectors as i32)?;
        {
            let mut mtf_selectors = 0x00654321i32;
            for i in 0..n_selectors {
                let ll_i = self.selectors[i] as i32;
                let bit_pos = ll_i << 2;
                let mtf_sel = (mtf_selectors >> bit_pos) & 0xF;

                // Move to front if not already there (rank 1 = already at front).
                if mtf_sel != 1 {
                    let inc_mask = (0x00888888i32
                        .wrapping_sub(mtf_selectors)
                        .wrapping_add(0x00111111i32.wrapping_mul(mtf_sel)))
                        & 0x00888888i32;
                    mtf_selectors = mtf_selectors
                        .wrapping_sub(mtf_sel << bit_pos)
                        .wrapping_add(inc_mask >> 3);
                }

                // Write (rank-1) ones followed by one 0:
                // (1 << rank) - 2  in  rank  bits produces 0b111...10.
                self.bs_put_bits_small(mtf_sel, (1 << mtf_sel) - 2)?;
            }
        }

        // Coding tables: delta-encoded lengths.
        // Symbol 0: 5-bit length packed with a 0-bit terminator into 6 bits.
        // Symbols 1+: pairs of "10" (increment) or "11" (decrement) then "0" (stop).
        for len_t in len.iter().take(n_groups) {
            let mut curr = len_t[0] as i32;
            self.bs_put_bits_small(6, curr << 1)?;
            for &l in len_t[1..alpha_size].iter() {
                let lti = l as i32;
                while curr < lti {
                    self.bs_put_bits_small(2, 2)?;
                    curr += 1;
                } // 10
                while curr > lti {
                    self.bs_put_bits_small(2, 3)?;
                    curr -= 1;
                } // 11
                self.bs_put_bit(0)?; // stop
            }
        }

        // Block data: Huffman-encode each MTF symbol using the selected table.
        let mut sel_ctr = 0usize;
        let mut gs = 0usize;
        while gs < self.n_mtf {
            let ge = (gs + G_SIZE - 1).min(self.n_mtf - 1);
            let sel = self.selectors[sel_ctr] as usize;
            for i in gs..=ge {
                let sym = self.zptr[i] as usize;
                self.bs_put_bits(len[sel][sym] as i32, code[sel][sym])?;
            }
            gs = ge + 1;
            sel_ctr += 1;
        }
        debug_assert!(sel_ctr == n_selectors);

        Ok(())
    }

    /// Build Huffman code lengths from symbol frequencies using a min-heap.
    /// If any length exceeds `max_len`, halve all weights and retry.
    fn hb_make_code_lengths(len: &mut [u8], freq: &[i32], alpha_size: usize, max_len: usize) {
        // Heap, weight, and parent arrays are 1-indexed; index 0 is a sentinel.
        let mut heap = [0i32; MAX_ALPHA_SIZE + 2];
        let mut weight = [0i32; MAX_ALPHA_SIZE * 2];
        let mut parent = [0i32; MAX_ALPHA_SIZE * 2];

        // Leaf weights: high 24 bits hold frequency, low 8 bits hold depth (0).
        for i in 0..alpha_size {
            weight[i + 1] = (if freq[i] == 0 { 1 } else { freq[i] }) << 8;
        }

        loop {
            let mut n_nodes = alpha_size;
            let mut n_heap = 0usize;

            heap[0] = 0;
            weight[0] = 0;
            parent[0] = -2;

            // Insert all leaf nodes into the min-heap.
            for (i, p) in parent.iter_mut().enumerate().skip(1).take(alpha_size) {
                *p = -1;
                n_heap += 1;
                heap[n_heap] = i as i32;
                // Sift up.
                let mut zz = n_heap;
                let tmp = heap[zz];
                while weight[tmp as usize] < weight[heap[zz >> 1] as usize] {
                    heap[zz] = heap[zz >> 1];
                    zz >>= 1;
                }
                heap[zz] = tmp;
            }
            debug_assert!(n_heap < MAX_ALPHA_SIZE + 2);

            // Build Huffman tree by repeatedly merging the two lightest nodes.
            while n_heap > 1 {
                // Extract minimum → n1.
                let n1 = heap[1];
                heap[1] = heap[n_heap];
                n_heap -= 1;
                Self::sift_down(&mut heap, &weight, n_heap, 1);

                // Extract minimum → n2.
                let n2 = heap[1];
                heap[1] = heap[n_heap];
                n_heap -= 1;
                Self::sift_down(&mut heap, &weight, n_heap, 1);

                // Create internal node combining n1 and n2.
                n_nodes += 1;
                parent[n1 as usize] = n_nodes as i32;
                parent[n2 as usize] = n_nodes as i32;

                let w1 = weight[n1 as usize];
                let w2 = weight[n2 as usize];
                weight[n_nodes] = (((w1 as u32 & 0xFFFFFF00) + (w2 as u32 & 0xFFFFFF00))
                    | (1 + (w1 & 0xFF).max(w2 & 0xFF) as u32))
                    as i32;

                parent[n_nodes] = -1;
                n_heap += 1;
                heap[n_heap] = n_nodes as i32;
                // Sift up.
                let mut zz = n_heap;
                let tmp = heap[zz];
                while weight[tmp as usize] < weight[heap[zz >> 1] as usize] {
                    heap[zz] = heap[zz >> 1];
                    zz >>= 1;
                }
                heap[zz] = tmp;
            }
            debug_assert!(n_nodes < MAX_ALPHA_SIZE * 2);

            // Compute code lengths as tree depths.
            let mut too_long_bits = 0i32;
            for i in 1..=alpha_size {
                let mut depth = 0i32;
                let mut k = i;
                while parent[k] >= 0 {
                    k = parent[k] as usize;
                    depth += 1;
                }
                len[i - 1] = depth as u8;
                too_long_bits |= max_len as i32 - depth;
            }

            if too_long_bits >= 0 {
                break; // All lengths within max_len.
            }

            // Some depths exceeded max_len: halve all leaf weights and retry.
            for w in weight[1..=alpha_size].iter_mut() {
                let j = *w >> 8;
                *w = (1 + j / 2) << 8;
            }
        }
    }

    /// Sift the element at `pos` down in the min-heap to restore heap order.
    fn sift_down(heap: &mut [i32], weight: &[i32], n_heap: usize, pos: usize) {
        let mut zz = pos;
        let tmp = heap[zz];
        loop {
            let mut yy = zz << 1;
            if yy > n_heap {
                break;
            }
            if yy < n_heap && weight[heap[yy + 1] as usize] < weight[heap[yy] as usize] {
                yy += 1;
            }
            if weight[tmp as usize] < weight[heap[yy] as usize] {
                break;
            }
            heap[zz] = heap[yy];
            zz = yy;
        }
        heap[zz] = tmp;
    }

    /// Assign canonical Huffman codes from code lengths.
    fn hb_assign_codes(
        code: &mut [i32],
        length: &[u8],
        min_len: i32,
        max_len: i32,
        alpha_size: usize,
    ) {
        let mut vec = 0i32;
        for n in min_len..=max_len {
            for i in 0..alpha_size {
                if length[i] as i32 == n {
                    code[i] = vec;
                    vec += 1;
                }
            }
            vec <<= 1;
        }
    }

    /// Flush any bits still sitting in `bs_buff` to the inner writer.
    ///
    /// After all blocks have been written the bit buffer may hold up to 7
    /// partial bits. They are padded with trailing zero bits to complete the
    /// last byte before writing.
    fn bs_finished_with_stream(&mut self) -> io::Result<()> {
        // bs_live_pos counts *free* positions in the 32-bit buffer, starting
        // at 32. Any value < 32 means at least one bit is waiting.
        while self.bs_live_pos < 32 {
            self.inner.write_all(&[(self.bs_buff >> 24) as u8])?;
            self.bs_buff <<= 8;
            self.bs_live_pos += 8;
        }
        Ok(())
    }

    /// Write the bzip2 end-of-stream marker and flush the bit buffer.
    ///
    /// Outputs:
    /// 1. The 48-bit EOS magic `0x177245385090` (a truncated hex encoding of
    ///    √π, chosen by the bzip2 spec to be distinct from the per-block magic).
    /// 2. The 32-bit combined stream CRC accumulated across all blocks.
    /// 3. Any partial bits left in the bit buffer, zero-padded to a full byte.
    fn end_compression(&mut self) -> io::Result<()> {
        self.bs_put_long48(0x177245385090)?;
        self.bs_put_int32(self.stream_crc)?;
        self.bs_finished_with_stream()
    }
}

impl<W: Write> Write for BZip2Writer<W> {
    /// 變動時間：依資料內容分支，只能用於公開值。
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for &byte in buf {
            self.write_byte_internal(byte)?;
        }
        Ok(buf.len())
    }

    /// 變動時間：依資料內容分支，只能用於公開值。
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> Drop for BZip2Writer<W> {
    /// 變動時間：依資料內容分支，只能用於公開值。
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Compress `data` with the given block size; returns the bzip2 bytes.
    ///
    /// `w` is scoped to a block so its borrow of `buf` is released before
    /// we return the vector.
    fn compress(data: &[u8], block_size: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = BZip2Writer::with_block_size(&mut buf, block_size).unwrap();
            w.write_all(data).unwrap();
            w.finish().unwrap();
        }
        buf
    }

    /// An empty bzip2 stream (block size 9) has a fixed 14-byte layout:
    ///   "BZh9"  (4 bytes)  stream header
    ///   EOS magic 0x177245385090  (6 bytes, big-endian 48-bit)
    ///   stream CRC 0x00000000  (4 bytes)
    /// No padding bytes because every field aligns to an octet boundary.
    #[test]
    fn empty_stream_exact_bytes() {
        let out = compress(b"", 9);
        assert_eq!(
            out,
            &[
                b'B', b'Z', b'h', b'9', // "BZh9"
                0x17, 0x72, 0x45, 0x38, 0x50, 0x90, // EOS magic √π
                0x00, 0x00, 0x00, 0x00, // stream CRC (no blocks)
            ]
        );
    }

    /// Block size digit in the header must reflect the requested level (1–9).
    #[test]
    fn header_block_size_digit() {
        for size in 1usize..=9 {
            let out = compress(b"", size);
            assert_eq!(
                &out[..4],
                &[b'B', b'Z', b'h', b'0' + size as u8],
                "wrong header for block_size={size}"
            );
        }
    }

    /// Block size is clamped: values outside 1–9 are accepted without panic.
    #[test]
    fn block_size_clamped() {
        let lo = compress(b"", 0); // clamped to 1 → 'BZh1'
        let hi = compress(b"", 99); // clamped to 9 → 'BZh9'
        assert_eq!(lo[3], b'1');
        assert_eq!(hi[3], b'9');
    }

    /// Writing data must not panic; output must start with the correct header.
    #[test]
    fn nonempty_stream_starts_with_header() {
        for data in [
            b"a".as_slice(),
            b"hello, world!",
            &[0u8; 1000],    // long run
            &[0u8; 100_001], // forces a block flush
        ] {
            let out = compress(data, 9);
            assert_eq!(
                &out[..3],
                b"BZh",
                "header mismatch for input len={}",
                data.len()
            );
        }
    }

    /// Calling finish() twice must produce the same output as calling it once
    /// (second call is a no-op).
    #[test]
    fn finish_idempotent() {
        // single finish via explicit call + Drop
        let mut once = Vec::new();
        {
            let mut w = BZip2Writer::new(&mut once).unwrap();
            w.finish().unwrap();
        }

        // two explicit finish() calls before Drop
        let mut twice = Vec::new();
        {
            let mut w = BZip2Writer::new(&mut twice).unwrap();
            w.finish().unwrap();
            w.finish().unwrap();
        }

        assert_eq!(once, twice);
    }
}
