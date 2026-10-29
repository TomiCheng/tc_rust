//! 移植自 zlib 1.3.2 的 `deflate.c`／`deflate.h`。只支援 zlib 與 raw deflate，
//! 視窗固定 15 位元、`memLevel` 固定 8；不含 gzip、預設字典與 `deflateParams`。

mod trees;

use crate::adler32;
use crate::constants::{CompressionLevel, FlushMode, Strategy};
use crate::deflate_options::DeflateOptions;
use crate::stream::{Status, Step};
use trees::{Bits, Trees};

const MAX_WBITS: usize = 15;
const DEF_MEM_LEVEL: usize = 8;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const MIN_LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH + 1;
const NIL: usize = 0;
const TOO_FAR: usize = 4096;
const WIN_INIT: usize = MAX_MATCH;
const MAX_STORED: usize = 65535;

struct Config {
    good_length: usize,
    max_lazy: usize,
    nice_length: usize,
    max_chain: usize,
}

const fn config(
    good_length: usize,
    max_lazy: usize,
    nice_length: usize,
    max_chain: usize,
) -> Config {
    Config {
        good_length,
        max_lazy,
        nice_length,
        max_chain,
    }
}

/// 第 0 級用 `deflate_stored`，1–3 級 `deflate_fast`，4–9 級 `deflate_slow`。
const CONFIGURATION_TABLE: [Config; 10] = [
    config(0, 0, 0, 0),
    config(4, 4, 8, 4),
    config(4, 5, 16, 8),
    config(4, 6, 32, 32),
    config(4, 4, 16, 16),
    config(8, 16, 32, 32),
    config(8, 16, 128, 128),
    config(8, 32, 128, 256),
    config(32, 128, 258, 1024),
    config(32, 258, 258, 4096),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockState {
    NeedMore,
    BlockDone,
    FinishStarted,
    FinishDone,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamStatus {
    Init,
    Busy,
    Finish,
}

/// C 的 `RANK()`；`None` 是 `last_flush` 的 -1／-2，兩者在比較時效果相同。
fn rank(flush: Option<FlushMode>) -> i32 {
    match flush {
        None => -2,
        Some(FlushMode::NoFlush) => 0,
        Some(FlushMode::SyncFlush) => 4,
        Some(FlushMode::FullFlush) => 6,
        Some(FlushMode::Finish) => 8,
    }
}

/// C 的 `z_stream` 中與這次呼叫有關的部分。
struct Strm<'a> {
    input: &'a [u8],
    next_in: usize,
    output: &'a mut [u8],
    next_out: usize,
}

impl Strm<'_> {
    fn avail_in(&self) -> usize {
        self.input.len() - self.next_in
    }

    fn avail_out(&self) -> usize {
        self.output.len() - self.next_out
    }
}

/// `FLUSH_BLOCK()`：送出區塊，輸出滿了就提早返回。
macro_rules! flush_block {
    ($s:expr, $strm:expr, $last:expr) => {{
        $s.flush_block_only($strm, $last);
        if $strm.avail_out() == 0 {
            return if $last {
                BlockState::FinishStarted
            } else {
                BlockState::NeedMore
            };
        }
    }};
}

pub(crate) struct DeflateState {
    status: StreamStatus,
    bits: Bits,
    wrap: i32,
    last_flush: Option<FlushMode>,
    adler: u32,
    w_size: usize,
    w_bits: usize,
    w_mask: usize,
    window: Vec<u8>,
    window_size: usize,
    prev: Vec<u16>,
    head: Vec<u16>,
    ins_h: usize,
    hash_mask: usize,
    hash_shift: usize,
    block_start: isize,
    match_length: usize,
    prev_match: usize,
    match_available: bool,
    strstart: usize,
    match_start: usize,
    lookahead: usize,
    prev_length: usize,
    max_chain_length: usize,
    max_lazy_match: usize,
    level: u32,
    strategy: Strategy,
    good_match: usize,
    nice_match: usize,
    trees: Trees,
    insert: usize,
    high_water: usize,
}

impl DeflateState {
    /// `deflateInit2()` 加 `deflateReset()`。
    pub(crate) fn new(options: &DeflateOptions) -> Self {
        let level = match options.level {
            CompressionLevel::None => 0,
            CompressionLevel::BestSpeed => 1,
            CompressionLevel::Default => 6,
            CompressionLevel::BestCompression => 9,
        };
        let w_bits = MAX_WBITS;
        let w_size = 1 << w_bits;
        let hash_bits = DEF_MEM_LEVEL + 7;
        let hash_size = 1 << hash_bits;
        let lit_bufsize = 1 << (DEF_MEM_LEVEL + 6);
        let cfg = &CONFIGURATION_TABLE[level as usize];

        Self {
            status: StreamStatus::Init,
            bits: Bits::new(lit_bufsize * 4),
            wrap: if options.nowrap { 0 } else { 1 },
            last_flush: None,
            adler: 1,
            w_size,
            w_bits,
            w_mask: w_size - 1,
            window: vec![0; 2 * w_size],
            window_size: 2 * w_size,
            prev: vec![0; w_size],
            head: vec![0; hash_size],
            ins_h: 0,
            hash_mask: hash_size - 1,
            hash_shift: hash_bits.div_ceil(MIN_MATCH),
            block_start: 0,
            match_length: MIN_MATCH - 1,
            prev_match: 0,
            match_available: false,
            strstart: 0,
            match_start: 0,
            lookahead: 0,
            prev_length: MIN_MATCH - 1,
            max_chain_length: cfg.max_chain,
            max_lazy_match: cfg.max_lazy,
            level,
            strategy: options.strategy,
            good_match: cfg.good_length,
            nice_match: cfg.nice_length,
            trees: Trees::new(lit_bufsize),
            insert: 0,
            high_water: 0,
        }
    }

    /// `deflate()`：盡量消耗 `input`、填滿 `output`。
    pub(crate) fn deflate(&mut self, input: &[u8], output: &mut [u8], flush: FlushMode) -> Step {
        let mut strm = Strm {
            input,
            next_in: 0,
            output,
            next_out: 0,
        };
        let status = self.run(&mut strm, flush);
        Step {
            read: strm.next_in,
            written: strm.next_out,
            status,
        }
    }

    fn run(&mut self, strm: &mut Strm<'_>, flush: FlushMode) -> Status {
        if self.status == StreamStatus::Finish && flush != FlushMode::Finish {
            return Status::StreamError;
        }
        if strm.avail_out() == 0 {
            return Status::BufError;
        }
        let old_flush = self.last_flush;
        self.last_flush = Some(flush);

        if self.bits.pending != 0 {
            self.flush_pending(strm);
            if strm.avail_out() == 0 {
                self.last_flush = None;
                return Status::Ok;
            }
        } else if strm.avail_in() == 0
            && rank(Some(flush)) <= rank(old_flush)
            && flush != FlushMode::Finish
        {
            return Status::BufError;
        }

        if self.status == StreamStatus::Finish && strm.avail_in() != 0 {
            return Status::BufError;
        }

        if self.status == StreamStatus::Init && self.wrap == 0 {
            self.status = StreamStatus::Busy;
        }
        if self.status == StreamStatus::Init {
            let mut header = (8 + ((self.w_bits as u32 - 8) << 4)) << 8;
            let level_flags = if matches!(
                self.strategy,
                Strategy::HuffmanOnly | Strategy::Rle | Strategy::Fixed
            ) || self.level < 2
            {
                0
            } else if self.level < 6 {
                1
            } else if self.level == 6 {
                2
            } else {
                3
            };
            header |= level_flags << 6;
            header += 31 - (header % 31);
            self.bits.put_short_msb(header);
            self.adler = 1;
            self.status = StreamStatus::Busy;

            self.flush_pending(strm);
            if self.bits.pending != 0 {
                self.last_flush = None;
                return Status::Ok;
            }
        }

        if strm.avail_in() != 0
            || self.lookahead != 0
            || (flush != FlushMode::NoFlush && self.status != StreamStatus::Finish)
        {
            let bstate = if self.level == 0 {
                self.deflate_stored(strm, flush)
            } else if self.strategy == Strategy::HuffmanOnly {
                self.deflate_huff(strm, flush)
            } else if self.strategy == Strategy::Rle {
                self.deflate_rle(strm, flush)
            } else if self.level <= 3 {
                self.deflate_fast(strm, flush)
            } else {
                self.deflate_slow(strm, flush)
            };

            if matches!(bstate, BlockState::FinishStarted | BlockState::FinishDone) {
                self.status = StreamStatus::Finish;
            }
            if matches!(bstate, BlockState::NeedMore | BlockState::FinishStarted) {
                if strm.avail_out() == 0 {
                    self.last_flush = None;
                }
                return Status::Ok;
            }
            if bstate == BlockState::BlockDone {
                // SyncFlush 與 FullFlush 都送一個空的 stored 區塊。
                self.bits.tr_stored_block(&[], false);
                if flush == FlushMode::FullFlush {
                    self.head.fill(0);
                    if self.lookahead == 0 {
                        self.strstart = 0;
                        self.block_start = 0;
                        self.insert = 0;
                    }
                }
                self.flush_pending(strm);
                if strm.avail_out() == 0 {
                    self.last_flush = None;
                    return Status::Ok;
                }
            }
        }

        if flush != FlushMode::Finish {
            return Status::Ok;
        }
        if self.wrap <= 0 {
            return Status::StreamEnd;
        }

        self.bits.put_short_msb(self.adler >> 16);
        self.bits.put_short_msb(self.adler & 0xffff);
        self.flush_pending(strm);
        self.wrap = -self.wrap;
        if self.bits.pending != 0 {
            Status::Ok
        } else {
            Status::StreamEnd
        }
    }

    fn max_dist(&self) -> usize {
        self.w_size - MIN_LOOKAHEAD
    }

    fn update_hash(&mut self, c: u8) {
        self.ins_h = ((self.ins_h << self.hash_shift) ^ usize::from(c)) & self.hash_mask;
    }

    /// `INSERT_STRING()`：回傳同一雜湊鏈上前一個位置。
    fn insert_string(&mut self, at: usize) -> usize {
        self.update_hash(self.window[at + MIN_MATCH - 1]);
        let head = self.head[self.ins_h];
        self.prev[at & self.w_mask] = head;
        self.head[self.ins_h] = at as u16;
        usize::from(head)
    }

    fn slide_hash(&mut self) {
        let wsize = self.w_size;
        for p in self.head.iter_mut().chain(self.prev.iter_mut()) {
            let m = usize::from(*p);
            *p = if m >= wsize {
                (m - wsize) as u16
            } else {
                NIL as u16
            };
        }
    }

    /// `read_buf()`：從輸入取最多 `size` bytes，並併入檢查碼。
    fn read_buf<'a>(&mut self, strm: &mut Strm<'a>, size: usize) -> &'a [u8] {
        let len = strm.avail_in().min(size);
        let input: &'a [u8] = strm.input;
        let data = &input[strm.next_in..strm.next_in + len];
        if self.wrap == 1 {
            self.adler = adler32::update(self.adler, data);
        }
        strm.next_in += len;
        data
    }

    fn flush_pending(&mut self, strm: &mut Strm<'_>) {
        self.bits.bi_flush();
        let len = self.bits.pending.min(strm.avail_out());
        if len == 0 {
            return;
        }
        let from = self.bits.pending_out;
        strm.output[strm.next_out..strm.next_out + len]
            .copy_from_slice(&self.bits.pending_buf[from..from + len]);
        strm.next_out += len;
        self.bits.pending_out += len;
        self.bits.pending -= len;
        if self.bits.pending == 0 {
            self.bits.pending_out = 0;
        }
    }

    fn fill_window(&mut self, strm: &mut Strm<'_>) {
        let wsize = self.w_size;
        loop {
            let mut more = self.window_size - self.lookahead - self.strstart;

            if self.strstart >= wsize + self.max_dist() {
                self.window.copy_within(wsize..2 * wsize - more, 0);
                self.match_start = self.match_start.wrapping_sub(wsize);
                self.strstart -= wsize;
                self.block_start -= wsize as isize;
                if self.insert > self.strstart {
                    self.insert = self.strstart;
                }
                self.slide_hash();
                more += wsize;
            }
            if strm.avail_in() == 0 {
                break;
            }

            let at = self.strstart + self.lookahead;
            let data = self.read_buf(strm, more);
            self.window[at..at + data.len()].copy_from_slice(data);
            self.lookahead += data.len();

            if self.lookahead + self.insert >= MIN_MATCH {
                let mut at = self.strstart - self.insert;
                self.ins_h = usize::from(self.window[at]);
                self.update_hash(self.window[at + 1]);
                while self.insert != 0 {
                    self.update_hash(self.window[at + MIN_MATCH - 1]);
                    self.prev[at & self.w_mask] = self.head[self.ins_h];
                    self.head[self.ins_h] = at as u16;
                    at += 1;
                    self.insert -= 1;
                    if self.lookahead + self.insert < MIN_MATCH {
                        break;
                    }
                }
            }

            if !(self.lookahead < MIN_LOOKAHEAD && strm.avail_in() != 0) {
                break;
            }
        }

        if self.high_water < self.window_size {
            let curr = self.strstart + self.lookahead;
            if self.high_water < curr {
                let init = (self.window_size - curr).min(WIN_INIT);
                self.window[curr..curr + init].fill(0);
                self.high_water = curr + init;
            } else if self.high_water < curr + WIN_INIT {
                let init =
                    (curr + WIN_INIT - self.high_water).min(self.window_size - self.high_water);
                self.window[self.high_water..self.high_water + init].fill(0);
                self.high_water += init;
            }
        }
    }

    fn longest_match(&mut self, mut cur_match: usize) -> usize {
        let mut chain_length = self.max_chain_length;
        let scan = self.strstart;
        let mut best_len = self.prev_length;
        let mut nice_match = self.nice_match;
        let limit = self.strstart.saturating_sub(self.max_dist());
        let wmask = self.w_mask;
        let window = &self.window;
        let prev = &self.prev;

        let mut scan_end1 = window[scan + best_len - 1];
        let mut scan_end = window[scan + best_len];

        if self.prev_length >= self.good_match {
            chain_length >>= 2;
        }
        if nice_match > self.lookahead {
            nice_match = self.lookahead;
        }

        loop {
            let m = cur_match;
            if window[m + best_len] == scan_end
                && window[m + best_len - 1] == scan_end1
                && window[m] == window[scan]
                && window[m + 1] == window[scan + 1]
            {
                // 第 2 個 byte 不比：雜湊值相同且前兩個 byte 相同時必然相等。
                let mut len = MIN_MATCH;
                while len < MAX_MATCH && window[scan + len] == window[m + len] {
                    len += 1;
                }
                if len > best_len {
                    self.match_start = cur_match;
                    best_len = len;
                    if len >= nice_match {
                        break;
                    }
                    scan_end1 = window[scan + best_len - 1];
                    scan_end = window[scan + best_len];
                }
            }

            cur_match = usize::from(prev[cur_match & wmask]);
            if cur_match <= limit {
                break;
            }
            chain_length -= 1;
            if chain_length == 0 {
                break;
            }
        }

        best_len.min(self.lookahead)
    }

    /// `FLUSH_BLOCK_ONLY()`。
    fn flush_block_only(&mut self, strm: &mut Strm<'_>, last: bool) {
        let stored_len = (self.strstart as isize - self.block_start) as usize;
        let buf = (self.block_start >= 0).then(|| {
            let start = self.block_start as usize;
            &self.window[start..start + stored_len]
        });
        self.trees.flush_block(
            &mut self.bits,
            buf,
            stored_len,
            last,
            self.level,
            self.strategy,
        );
        self.block_start = self.strstart as isize;
        self.flush_pending(strm);
    }

    fn deflate_stored(&mut self, strm: &mut Strm<'_>, flush: FlushMode) -> BlockState {
        let wsize = self.w_size;
        let mut min_block = (self.bits.pending_buf_size - 5).min(wsize);
        let mut last = false;
        let used = strm.avail_in();

        loop {
            let mut len = MAX_STORED;
            let header = (self.bits.bi_valid as usize + 42) >> 3;
            if strm.avail_out() < header {
                break;
            }
            let have = strm.avail_out() - header;
            let mut left = (self.strstart as isize - self.block_start) as usize;
            if len > left + strm.avail_in() {
                len = left + strm.avail_in();
            }
            if len > have {
                len = have;
            }

            if len < min_block
                && ((len == 0 && flush != FlushMode::Finish)
                    || flush == FlushMode::NoFlush
                    || len != left + strm.avail_in())
            {
                break;
            }

            last = flush == FlushMode::Finish && len == left + strm.avail_in();
            self.bits.tr_stored_block(&[], last);

            let end = self.bits.pending_out + self.bits.pending;
            self.bits.pending_buf[end - 4..end].copy_from_slice(&[
                len as u8,
                (len >> 8) as u8,
                !len as u8,
                (!len >> 8) as u8,
            ]);
            self.flush_pending(strm);

            if left != 0 {
                if left > len {
                    left = len;
                }
                let start = self.block_start as usize;
                strm.output[strm.next_out..strm.next_out + left]
                    .copy_from_slice(&self.window[start..start + left]);
                strm.next_out += left;
                self.block_start += left as isize;
                len -= left;
            }
            if len != 0 {
                let data = self.read_buf(strm, len);
                strm.output[strm.next_out..strm.next_out + len].copy_from_slice(data);
                strm.next_out += len;
            }
            if last {
                break;
            }
        }

        let used = used - strm.avail_in();
        if used != 0 {
            let input: &[u8] = strm.input;
            let consumed = &input[strm.next_in - used..strm.next_in];
            if used >= wsize {
                self.trees.matches = 2;
                self.window[..wsize].copy_from_slice(&consumed[used - wsize..]);
                self.strstart = wsize;
                self.insert = self.strstart;
            } else {
                if self.window_size - self.strstart <= used {
                    self.strstart -= wsize;
                    self.window.copy_within(wsize..wsize + self.strstart, 0);
                    if self.trees.matches < 2 {
                        self.trees.matches += 1;
                    }
                    if self.insert > self.strstart {
                        self.insert = self.strstart;
                    }
                }
                self.window[self.strstart..self.strstart + used].copy_from_slice(consumed);
                self.strstart += used;
                self.insert += used.min(wsize - self.insert);
            }
            self.block_start = self.strstart as isize;
        }
        if self.high_water < self.strstart {
            self.high_water = self.strstart;
        }

        if last {
            return BlockState::FinishDone;
        }

        if flush != FlushMode::NoFlush
            && flush != FlushMode::Finish
            && strm.avail_in() == 0
            && self.strstart as isize == self.block_start
        {
            return BlockState::BlockDone;
        }

        let mut have = self.window_size - self.strstart;
        if strm.avail_in() > have && self.block_start >= wsize as isize {
            self.block_start -= wsize as isize;
            self.strstart -= wsize;
            self.window.copy_within(wsize..wsize + self.strstart, 0);
            if self.trees.matches < 2 {
                self.trees.matches += 1;
            }
            have += wsize;
            if self.insert > self.strstart {
                self.insert = self.strstart;
            }
        }
        if have > strm.avail_in() {
            have = strm.avail_in();
        }
        if have != 0 {
            let data = self.read_buf(strm, have);
            self.window[self.strstart..self.strstart + have].copy_from_slice(data);
            self.strstart += have;
            self.insert += have.min(wsize - self.insert);
        }
        if self.high_water < self.strstart {
            self.high_water = self.strstart;
        }

        let header = (self.bits.bi_valid as usize + 42) >> 3;
        let have = (self.bits.pending_buf_size - header).min(MAX_STORED);
        min_block = have.min(wsize);
        let left = (self.strstart as isize - self.block_start) as usize;
        if left >= min_block
            || ((left != 0 || flush == FlushMode::Finish)
                && flush != FlushMode::NoFlush
                && strm.avail_in() == 0
                && left <= have)
        {
            let len = left.min(have);
            last = flush == FlushMode::Finish && strm.avail_in() == 0 && len == left;
            let start = self.block_start as usize;
            self.bits
                .tr_stored_block(&self.window[start..start + len], last);
            self.block_start += len as isize;
            self.flush_pending(strm);
        }

        if last {
            BlockState::FinishStarted
        } else {
            BlockState::NeedMore
        }
    }

    fn deflate_fast(&mut self, strm: &mut Strm<'_>, flush: FlushMode) -> BlockState {
        loop {
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(strm);
                if self.lookahead < MIN_LOOKAHEAD && flush == FlushMode::NoFlush {
                    return BlockState::NeedMore;
                }
                if self.lookahead == 0 {
                    break;
                }
            }

            let mut hash_head = NIL;
            if self.lookahead >= MIN_MATCH {
                hash_head = self.insert_string(self.strstart);
            }
            if hash_head != NIL && self.strstart.wrapping_sub(hash_head) <= self.max_dist() {
                self.match_length = self.longest_match(hash_head);
            }

            let bflush;
            if self.match_length >= MIN_MATCH {
                bflush = self.trees.tally(
                    self.strstart.wrapping_sub(self.match_start),
                    self.match_length - MIN_MATCH,
                );
                self.lookahead -= self.match_length;
                if self.match_length <= self.max_lazy_match && self.lookahead >= MIN_MATCH {
                    self.match_length -= 1;
                    loop {
                        self.strstart += 1;
                        self.insert_string(self.strstart);
                        self.match_length -= 1;
                        if self.match_length == 0 {
                            break;
                        }
                    }
                    self.strstart += 1;
                } else {
                    self.strstart += self.match_length;
                    self.match_length = 0;
                    self.ins_h = usize::from(self.window[self.strstart]);
                    self.update_hash(self.window[self.strstart + 1]);
                }
            } else {
                bflush = self.trees.tally(0, usize::from(self.window[self.strstart]));
                self.lookahead -= 1;
                self.strstart += 1;
            }
            if bflush {
                flush_block!(self, strm, false);
            }
        }

        self.insert = self.strstart.min(MIN_MATCH - 1);
        if flush == FlushMode::Finish {
            flush_block!(self, strm, true);
            return BlockState::FinishDone;
        }
        if self.trees.sym_next != 0 {
            flush_block!(self, strm, false);
        }
        BlockState::BlockDone
    }

    fn deflate_slow(&mut self, strm: &mut Strm<'_>, flush: FlushMode) -> BlockState {
        loop {
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(strm);
                if self.lookahead < MIN_LOOKAHEAD && flush == FlushMode::NoFlush {
                    return BlockState::NeedMore;
                }
                if self.lookahead == 0 {
                    break;
                }
            }

            let mut hash_head = NIL;
            if self.lookahead >= MIN_MATCH {
                hash_head = self.insert_string(self.strstart);
            }

            self.prev_length = self.match_length;
            self.prev_match = self.match_start;
            self.match_length = MIN_MATCH - 1;

            if hash_head != NIL
                && self.prev_length < self.max_lazy_match
                && self.strstart.wrapping_sub(hash_head) <= self.max_dist()
            {
                self.match_length = self.longest_match(hash_head);
                if self.match_length <= 5
                    && (self.strategy == Strategy::Filtered
                        || (self.match_length == MIN_MATCH
                            && self.strstart.wrapping_sub(self.match_start) > TOO_FAR))
                {
                    self.match_length = MIN_MATCH - 1;
                }
            }

            if self.prev_length >= MIN_MATCH && self.match_length <= self.prev_length {
                let max_insert = (self.strstart + self.lookahead).wrapping_sub(MIN_MATCH);
                let bflush = self.trees.tally(
                    self.strstart.wrapping_sub(1).wrapping_sub(self.prev_match),
                    self.prev_length - MIN_MATCH,
                );
                self.lookahead -= self.prev_length - 1;
                self.prev_length -= 2;
                loop {
                    self.strstart += 1;
                    if self.strstart <= max_insert {
                        self.insert_string(self.strstart);
                    }
                    self.prev_length -= 1;
                    if self.prev_length == 0 {
                        break;
                    }
                }
                self.match_available = false;
                self.match_length = MIN_MATCH - 1;
                self.strstart += 1;
                if bflush {
                    flush_block!(self, strm, false);
                }
            } else if self.match_available {
                let bflush = self
                    .trees
                    .tally(0, usize::from(self.window[self.strstart - 1]));
                if bflush {
                    self.flush_block_only(strm, false);
                }
                self.strstart += 1;
                self.lookahead -= 1;
                if strm.avail_out() == 0 {
                    return BlockState::NeedMore;
                }
            } else {
                self.match_available = true;
                self.strstart += 1;
                self.lookahead -= 1;
            }
        }

        if self.match_available {
            self.trees
                .tally(0, usize::from(self.window[self.strstart - 1]));
            self.match_available = false;
        }
        self.insert = self.strstart.min(MIN_MATCH - 1);
        if flush == FlushMode::Finish {
            flush_block!(self, strm, true);
            return BlockState::FinishDone;
        }
        if self.trees.sym_next != 0 {
            flush_block!(self, strm, false);
        }
        BlockState::BlockDone
    }

    fn deflate_rle(&mut self, strm: &mut Strm<'_>, flush: FlushMode) -> BlockState {
        loop {
            if self.lookahead <= MAX_MATCH {
                self.fill_window(strm);
                if self.lookahead <= MAX_MATCH && flush == FlushMode::NoFlush {
                    return BlockState::NeedMore;
                }
                if self.lookahead == 0 {
                    break;
                }
            }

            self.match_length = 0;
            if self.lookahead >= MIN_MATCH && self.strstart > 0 {
                let at = self.strstart;
                let prev = self.window[at - 1];
                if prev == self.window[at]
                    && prev == self.window[at + 1]
                    && prev == self.window[at + 2]
                {
                    let mut len = MIN_MATCH;
                    while len < MAX_MATCH && self.window[at + len] == prev {
                        len += 1;
                    }
                    self.match_length = len.min(self.lookahead);
                }
            }

            let bflush;
            if self.match_length >= MIN_MATCH {
                bflush = self.trees.tally(1, self.match_length - MIN_MATCH);
                self.lookahead -= self.match_length;
                self.strstart += self.match_length;
                self.match_length = 0;
            } else {
                bflush = self.trees.tally(0, usize::from(self.window[self.strstart]));
                self.lookahead -= 1;
                self.strstart += 1;
            }
            if bflush {
                flush_block!(self, strm, false);
            }
        }

        self.insert = 0;
        if flush == FlushMode::Finish {
            flush_block!(self, strm, true);
            return BlockState::FinishDone;
        }
        if self.trees.sym_next != 0 {
            flush_block!(self, strm, false);
        }
        BlockState::BlockDone
    }

    fn deflate_huff(&mut self, strm: &mut Strm<'_>, flush: FlushMode) -> BlockState {
        loop {
            if self.lookahead == 0 {
                self.fill_window(strm);
                if self.lookahead == 0 {
                    if flush == FlushMode::NoFlush {
                        return BlockState::NeedMore;
                    }
                    break;
                }
            }

            self.match_length = 0;
            let bflush = self.trees.tally(0, usize::from(self.window[self.strstart]));
            self.lookahead -= 1;
            self.strstart += 1;
            if bflush {
                flush_block!(self, strm, false);
            }
        }

        self.insert = 0;
        if flush == FlushMode::Finish {
            flush_block!(self, strm, true);
            return BlockState::FinishDone;
        }
        if self.trees.sym_next != 0 {
            flush_block!(self, strm, false);
        }
        BlockState::BlockDone
    }
}
