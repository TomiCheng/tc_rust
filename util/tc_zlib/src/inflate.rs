//! 移植自 zlib 1.3.2 的 `inflate.c`／`inflate.h`。只支援 zlib 與 raw deflate，
//! 不含 gzip、`Z_BLOCK`／`Z_TREES` 與預設字典。

mod inffast;
mod inftrees;

use crate::adler32;
use crate::constants::FlushMode;
use crate::inflate_options::InflateOptions;
use crate::stream::{Status, Step};
use inftrees::{Code, CodeType, DISTFIX, ENOUGH, LENFIX, inflate_table};

/// 與 C 的 `inflate_mode` 同序；`inf_leave` 用到 `< Check`、`< Bad` 的比較。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Mode {
    Head,
    DictId,
    Dict,
    Type,
    Stored,
    Copy,
    Table,
    LenLens,
    CodeLens,
    Len,
    LenExt,
    Dist,
    DistExt,
    Match,
    Lit,
    Check,
    Done,
    Bad,
}

/// C 的 `lencode`／`distcode` 指標：指向固定表或 `codes` 裡的某個位置。
#[derive(Clone, Copy)]
enum Table {
    LenFix,
    DistFix,
    Codes(usize),
}

impl Table {
    fn slice(self, codes: &[Code]) -> &[Code] {
        match self {
            Table::LenFix => &LENFIX,
            Table::DistFix => &DISTFIX,
            Table::Codes(at) => &codes[at..],
        }
    }
}

const ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

pub(crate) struct InflateState {
    mode: Mode,
    msg: &'static str,
    last: bool,
    wrap: bool,
    check: u32,
    wbits: u32,
    wsize: usize,
    whave: usize,
    wnext: usize,
    window: Vec<u8>,
    hold: u64,
    bits: u32,
    length: usize,
    offset: usize,
    extra: u32,
    lencode: Table,
    distcode: Table,
    lenbits: u32,
    distbits: u32,
    ncode: usize,
    nlen: usize,
    ndist: usize,
    have: usize,
    next: usize,
    lens: [u16; 320],
    work: [u16; 288],
    codes: [Code; ENOUGH],
}

/// 由 `from` 往前複製 `len` bytes 到 `to`；兩者重疊時逐 byte 複製，
/// 讓距離小於長度的比對能重複剛寫出的內容。
fn copy_match(output: &mut [u8], from: usize, to: usize, len: usize) {
    if to - from >= len {
        output.copy_within(from..from + len, to);
    } else {
        for i in 0..len {
            output[to + i] = output[from + i];
        }
    }
}

impl InflateState {
    /// `inflateInit2()`：視窗固定 15 位元。
    pub(crate) fn new(options: &InflateOptions) -> Self {
        Self {
            mode: Mode::Head,
            msg: "",
            last: false,
            wrap: !options.nowrap,
            check: 1,
            wbits: 15,
            wsize: 0,
            whave: 0,
            wnext: 0,
            window: Vec::new(),
            hold: 0,
            bits: 0,
            length: 0,
            offset: 0,
            extra: 0,
            lencode: Table::Codes(0),
            distcode: Table::Codes(0),
            lenbits: 0,
            distbits: 0,
            ncode: 0,
            nlen: 0,
            ndist: 0,
            have: 0,
            next: 0,
            lens: [0; 320],
            work: [0; 288],
            codes: [Code::default(); ENOUGH],
        }
    }

    /// `updatewindow()`：把剛寫出的 `recent` 併入循環視窗。
    fn update_window(&mut self, recent: &[u8]) {
        if self.window.is_empty() {
            self.window = vec![0; 1 << self.wbits];
        }
        if self.wsize == 0 {
            self.wsize = 1 << self.wbits;
            self.wnext = 0;
            self.whave = 0;
        }
        let copy = recent.len();
        let wsize = self.wsize;
        if copy >= wsize {
            self.window[..wsize].copy_from_slice(&recent[copy - wsize..]);
            self.wnext = 0;
            self.whave = wsize;
        } else {
            let dist = (wsize - self.wnext).min(copy);
            self.window[self.wnext..self.wnext + dist].copy_from_slice(&recent[..dist]);
            let copy = copy - dist;
            if copy != 0 {
                self.window[..copy].copy_from_slice(&recent[dist..]);
                self.wnext = copy;
                self.whave = wsize;
            } else {
                self.wnext += dist;
                if self.wnext == wsize {
                    self.wnext = 0;
                }
                if self.whave < wsize {
                    self.whave += dist;
                }
            }
        }
    }

    /// `inflate()`：盡量消耗 `input`、填滿 `output`。
    pub(crate) fn inflate(&mut self, input: &[u8], output: &mut [u8], flush: FlushMode) -> Step {
        let mut next = 0usize;
        let mut put = 0usize;
        let mut hold = self.hold;
        let mut bits = self.bits;
        // C 的 `out`：還沒併入檢查碼的輸出從這裡開始。
        let mut mark = 0usize;
        let mut ret = Status::Ok;

        'leave: loop {
            // 巨集定義在迴圈裡，`'leave` 標籤才對巨集可見。
            macro_rules! pull_byte {
                () => {{
                    if next == input.len() {
                        break 'leave;
                    }
                    hold += u64::from(input[next]) << bits;
                    next += 1;
                    bits += 8;
                }};
            }
            macro_rules! need_bits {
                ($n:expr) => {{
                    while bits < ($n) as u32 {
                        pull_byte!();
                    }
                }};
            }
            macro_rules! bits_of {
                ($n:expr) => {
                    (hold & ((1u64 << ($n)) - 1)) as u32
                };
            }
            macro_rules! drop_bits {
                ($n:expr) => {{
                    let n = ($n) as u32;
                    hold >>= n;
                    bits -= n;
                }};
            }
            macro_rules! init_bits {
                () => {{
                    hold = 0;
                    bits = 0;
                }};
            }
            macro_rules! bad {
                ($msg:expr) => {{
                    self.msg = $msg;
                    self.mode = Mode::Bad;
                    continue 'leave;
                }};
            }

            match self.mode {
                Mode::Head => {
                    if !self.wrap {
                        self.mode = Mode::Type;
                        continue;
                    }
                    need_bits!(16);
                    if ((bits_of!(8) << 8) + (hold >> 8) as u32) % 31 != 0 {
                        bad!("incorrect header check");
                    }
                    if bits_of!(4) != 8 {
                        bad!("unknown compression method");
                    }
                    drop_bits!(4);
                    let len = bits_of!(4) + 8;
                    if len > 15 || len > self.wbits {
                        bad!("invalid window size");
                    }
                    self.check = 1;
                    self.mode = if hold & 0x200 != 0 {
                        Mode::DictId
                    } else {
                        Mode::Type
                    };
                    init_bits!();
                }
                Mode::DictId => {
                    need_bits!(32);
                    self.check = (hold as u32).swap_bytes();
                    init_bits!();
                    self.mode = Mode::Dict;
                }
                Mode::Dict => {
                    self.hold = hold;
                    self.bits = bits;
                    return Step {
                        read: next,
                        written: put,
                        status: Status::NeedDict,
                    };
                }
                Mode::Type => {
                    if self.last {
                        hold >>= bits & 7;
                        bits -= bits & 7;
                        self.mode = Mode::Check;
                        continue;
                    }
                    need_bits!(3);
                    self.last = bits_of!(1) != 0;
                    drop_bits!(1);
                    match bits_of!(2) {
                        0 => self.mode = Mode::Stored,
                        1 => {
                            self.lencode = Table::LenFix;
                            self.lenbits = 9;
                            self.distcode = Table::DistFix;
                            self.distbits = 5;
                            self.mode = Mode::Len;
                        }
                        2 => self.mode = Mode::Table,
                        _ => {
                            self.msg = "invalid block type";
                            self.mode = Mode::Bad;
                        }
                    }
                    drop_bits!(2);
                }
                Mode::Stored => {
                    hold >>= bits & 7;
                    bits -= bits & 7;
                    need_bits!(32);
                    if (hold & 0xffff) != ((hold >> 16) ^ 0xffff) {
                        bad!("invalid stored block lengths");
                    }
                    self.length = (hold & 0xffff) as usize;
                    init_bits!();
                    self.mode = Mode::Copy;
                }
                Mode::Copy => {
                    let mut copy = self.length;
                    if copy != 0 {
                        copy = copy.min(input.len() - next).min(output.len() - put);
                        if copy == 0 {
                            break 'leave;
                        }
                        output[put..put + copy].copy_from_slice(&input[next..next + copy]);
                        next += copy;
                        put += copy;
                        self.length -= copy;
                        continue;
                    }
                    self.mode = Mode::Type;
                }
                Mode::Table => {
                    need_bits!(14);
                    self.nlen = bits_of!(5) as usize + 257;
                    drop_bits!(5);
                    self.ndist = bits_of!(5) as usize + 1;
                    drop_bits!(5);
                    self.ncode = bits_of!(4) as usize + 4;
                    drop_bits!(4);
                    if self.nlen > 286 || self.ndist > 30 {
                        bad!("too many length or distance symbols");
                    }
                    self.have = 0;
                    self.mode = Mode::LenLens;
                }
                Mode::LenLens => {
                    while self.have < self.ncode {
                        need_bits!(3);
                        self.lens[ORDER[self.have]] = bits_of!(3) as u16;
                        self.have += 1;
                        drop_bits!(3);
                    }
                    while self.have < 19 {
                        self.lens[ORDER[self.have]] = 0;
                        self.have += 1;
                    }
                    self.next = 0;
                    self.lencode = Table::Codes(0);
                    self.distcode = Table::Codes(0);
                    self.lenbits = 7;
                    let ret = inflate_table(
                        CodeType::Codes,
                        &self.lens[..19],
                        &mut self.codes,
                        &mut self.next,
                        &mut self.lenbits,
                        &mut self.work,
                    );
                    if ret != 0 {
                        bad!("invalid code lengths set");
                    }
                    self.have = 0;
                    self.mode = Mode::CodeLens;
                }
                Mode::CodeLens => {
                    while self.have < self.nlen + self.ndist {
                        let lcode = self.lencode.slice(&self.codes);
                        let here = loop {
                            let here = lcode[bits_of!(self.lenbits) as usize];
                            if u32::from(here.bits) <= bits {
                                break here;
                            }
                            pull_byte!();
                        };
                        if here.val < 16 {
                            drop_bits!(here.bits);
                            self.lens[self.have] = here.val;
                            self.have += 1;
                        } else {
                            let (len, copy) = if here.val == 16 {
                                need_bits!(here.bits + 2);
                                drop_bits!(here.bits);
                                if self.have == 0 {
                                    bad!("invalid bit length repeat");
                                }
                                let len = self.lens[self.have - 1];
                                let copy = 3 + bits_of!(2) as usize;
                                drop_bits!(2);
                                (len, copy)
                            } else if here.val == 17 {
                                need_bits!(here.bits + 3);
                                drop_bits!(here.bits);
                                let copy = 3 + bits_of!(3) as usize;
                                drop_bits!(3);
                                (0, copy)
                            } else {
                                need_bits!(here.bits + 7);
                                drop_bits!(here.bits);
                                let copy = 11 + bits_of!(7) as usize;
                                drop_bits!(7);
                                (0, copy)
                            };
                            if self.have + copy > self.nlen + self.ndist {
                                bad!("invalid bit length repeat");
                            }
                            self.lens[self.have..self.have + copy].fill(len);
                            self.have += copy;
                        }
                    }

                    if self.lens[256] == 0 {
                        bad!("invalid code -- missing end-of-block");
                    }

                    self.next = 0;
                    self.lencode = Table::Codes(self.next);
                    self.lenbits = 9;
                    let ret = inflate_table(
                        CodeType::Lens,
                        &self.lens[..self.nlen],
                        &mut self.codes,
                        &mut self.next,
                        &mut self.lenbits,
                        &mut self.work,
                    );
                    if ret != 0 {
                        bad!("invalid literal/lengths set");
                    }
                    self.distcode = Table::Codes(self.next);
                    self.distbits = 6;
                    let ret = inflate_table(
                        CodeType::Dists,
                        &self.lens[self.nlen..self.nlen + self.ndist],
                        &mut self.codes,
                        &mut self.next,
                        &mut self.distbits,
                        &mut self.work,
                    );
                    if ret != 0 {
                        bad!("invalid distances set");
                    }
                    self.mode = Mode::Len;
                }
                Mode::Len => {
                    if input.len() - next >= 6 && output.len() - put >= 258 {
                        self.inflate_fast(
                            input, &mut next, output, &mut put, mark, &mut hold, &mut bits,
                        );
                        continue;
                    }
                    let lcode = self.lencode.slice(&self.codes);
                    let mut here = loop {
                        let here = lcode[bits_of!(self.lenbits) as usize];
                        if u32::from(here.bits) <= bits {
                            break here;
                        }
                        pull_byte!();
                    };
                    if here.op != 0 && here.op & 0xf0 == 0 {
                        let last = here;
                        here = loop {
                            let at = usize::from(last.val)
                                + (bits_of!(last.bits + last.op) >> last.bits) as usize;
                            let here = lcode[at];
                            if u32::from(last.bits) + u32::from(here.bits) <= bits {
                                break here;
                            }
                            pull_byte!();
                        };
                        drop_bits!(last.bits);
                    }
                    drop_bits!(here.bits);
                    self.length = usize::from(here.val);
                    if here.op == 0 {
                        self.mode = Mode::Lit;
                        continue;
                    }
                    if here.op & 32 != 0 {
                        self.mode = Mode::Type;
                        continue;
                    }
                    if here.op & 64 != 0 {
                        bad!("invalid literal/length code");
                    }
                    self.extra = u32::from(here.op) & 15;
                    self.mode = Mode::LenExt;
                }
                Mode::LenExt => {
                    if self.extra != 0 {
                        need_bits!(self.extra);
                        self.length += bits_of!(self.extra) as usize;
                        drop_bits!(self.extra);
                    }
                    self.mode = Mode::Dist;
                }
                Mode::Dist => {
                    let dcode = self.distcode.slice(&self.codes);
                    let mut here = loop {
                        let here = dcode[bits_of!(self.distbits) as usize];
                        if u32::from(here.bits) <= bits {
                            break here;
                        }
                        pull_byte!();
                    };
                    if here.op & 0xf0 == 0 {
                        let last = here;
                        here = loop {
                            let at = usize::from(last.val)
                                + (bits_of!(last.bits + last.op) >> last.bits) as usize;
                            let here = dcode[at];
                            if u32::from(last.bits) + u32::from(here.bits) <= bits {
                                break here;
                            }
                            pull_byte!();
                        };
                        drop_bits!(last.bits);
                    }
                    drop_bits!(here.bits);
                    if here.op & 64 != 0 {
                        bad!("invalid distance code");
                    }
                    self.offset = usize::from(here.val);
                    self.extra = u32::from(here.op) & 15;
                    self.mode = Mode::DistExt;
                }
                Mode::DistExt => {
                    if self.extra != 0 {
                        need_bits!(self.extra);
                        self.offset += bits_of!(self.extra) as usize;
                        drop_bits!(self.extra);
                    }
                    self.mode = Mode::Match;
                }
                Mode::Match => {
                    let left = output.len() - put;
                    if left == 0 {
                        break 'leave;
                    }
                    let produced = put - mark;
                    let mut copy;
                    if self.offset > produced {
                        copy = self.offset - produced;
                        if copy > self.whave {
                            bad!("invalid distance too far back");
                        }
                        let from = if copy > self.wnext {
                            copy -= self.wnext;
                            self.wsize - copy
                        } else {
                            self.wnext - copy
                        };
                        copy = copy.min(self.length).min(left);
                        output[put..put + copy].copy_from_slice(&self.window[from..from + copy]);
                    } else {
                        copy = self.length.min(left);
                        copy_match(output, put - self.offset, put, copy);
                    }
                    put += copy;
                    self.length -= copy;
                    if self.length == 0 {
                        self.mode = Mode::Len;
                    }
                }
                Mode::Lit => {
                    if put == output.len() {
                        break 'leave;
                    }
                    output[put] = self.length as u8;
                    put += 1;
                    self.mode = Mode::Len;
                }
                Mode::Check => {
                    if self.wrap {
                        need_bits!(32);
                        if put > mark {
                            self.check = adler32::update(self.check, &output[mark..put]);
                        }
                        mark = put;
                        if (hold as u32).swap_bytes() != self.check {
                            bad!("incorrect data check");
                        }
                        init_bits!();
                    }
                    self.mode = Mode::Done;
                }
                Mode::Done => {
                    ret = Status::StreamEnd;
                    break 'leave;
                }
                Mode::Bad => {
                    ret = Status::DataError(self.msg);
                    break 'leave;
                }
            }
        }

        self.hold = hold;
        self.bits = bits;
        if self.wsize != 0
            || (put != mark
                && self.mode < Mode::Bad
                && (self.mode < Mode::Check || flush != FlushMode::Finish))
        {
            self.update_window(&output[mark..put]);
        }
        if self.wrap && put > mark {
            self.check = adler32::update(self.check, &output[mark..put]);
        }
        if ((next == 0 && put == mark) || flush == FlushMode::Finish) && ret == Status::Ok {
            ret = Status::BufError;
        }
        Step {
            read: next,
            written: put,
            status: ret,
        }
    }
}
