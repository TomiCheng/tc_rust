//! 移植自 zlib 1.3.2 的 `inffast.c`：輸入與輸出都夠多時的快速解碼迴圈。

use super::inftrees::Code;
use super::{InflateState, Mode, copy_match};

enum From {
    Window(usize),
    Output(usize),
}

impl InflateState {
    /// 前提：`input` 從 `*next` 起至少 6 bytes，`output` 從 `*put` 起至少 258 bytes。
    /// `beg` 是這次呼叫輸出的起點，用來判斷距離是否要回頭讀視窗。
    #[allow(clippy::too_many_arguments)]
    pub(super) fn inflate_fast(
        &mut self,
        input: &[u8],
        next: &mut usize,
        output: &mut [u8],
        put: &mut usize,
        beg: usize,
        hold: &mut u64,
        bits: &mut u32,
    ) {
        let last = input.len() - 5;
        let end = output.len() - 257;
        let lcode: &[Code] = self.lencode.slice(&self.codes);
        let dcode: &[Code] = self.distcode.slice(&self.codes);
        let lmask = (1u64 << self.lenbits) - 1;
        let dmask = (1u64 << self.distbits) - 1;
        let (wsize, whave, wnext) = (self.wsize, self.whave, self.wnext);
        let window = &self.window[..];

        let mut inp = *next;
        let mut out = *put;
        let mut h = *hold;
        let mut b = *bits;
        let mut stop: Option<(Mode, &'static str)> = None;

        macro_rules! load {
            () => {{
                h += u64::from(input[inp]) << b;
                inp += 1;
                b += 8;
            }};
        }
        macro_rules! low_bits {
            ($n:expr) => {
                h & ((1u64 << $n) - 1)
            };
        }

        'decode: loop {
            if b < 15 {
                load!();
                load!();
            }
            let mut here = lcode[(h & lmask) as usize];
            'dolen: loop {
                let op = u32::from(here.bits);
                h >>= op;
                b -= op;
                let op = u32::from(here.op);
                if op == 0 {
                    output[out] = here.val as u8;
                    out += 1;
                } else if op & 16 != 0 {
                    let mut len = usize::from(here.val);
                    let op = op & 15;
                    if op != 0 {
                        if b < op {
                            load!();
                        }
                        len += low_bits!(op) as usize;
                        h >>= op;
                        b -= op;
                    }
                    if b < 15 {
                        load!();
                        load!();
                    }
                    let mut here = dcode[(h & dmask) as usize];
                    loop {
                        let op = u32::from(here.bits);
                        h >>= op;
                        b -= op;
                        let op = u32::from(here.op);
                        if op & 16 != 0 {
                            let mut dist = usize::from(here.val);
                            let op = op & 15;
                            if b < op {
                                load!();
                                if b < op {
                                    load!();
                                }
                            }
                            dist += low_bits!(op) as usize;
                            h >>= op;
                            b -= op;
                            let produced = out - beg;
                            if dist > produced {
                                let mut op = dist - produced;
                                if op > whave {
                                    stop = Some((Mode::Bad, "invalid distance too far back"));
                                    break 'decode;
                                }
                                let mut from;
                                if wnext == 0 {
                                    from = From::Window(wsize - op);
                                    if op < len {
                                        len -= op;
                                        let at = wsize - op;
                                        output[out..out + op].copy_from_slice(&window[at..at + op]);
                                        out += op;
                                        from = From::Output(out - dist);
                                    }
                                } else if wnext < op {
                                    from = From::Window(wsize + wnext - op);
                                    op -= wnext;
                                    if op < len {
                                        len -= op;
                                        let at = wsize - op;
                                        output[out..out + op].copy_from_slice(&window[at..at + op]);
                                        out += op;
                                        from = From::Window(0);
                                        if wnext < len {
                                            op = wnext;
                                            len -= op;
                                            output[out..out + op].copy_from_slice(&window[..op]);
                                            out += op;
                                            from = From::Output(out - dist);
                                        }
                                    }
                                } else {
                                    from = From::Window(wnext - op);
                                    if op < len {
                                        len -= op;
                                        let at = wnext - op;
                                        output[out..out + op].copy_from_slice(&window[at..at + op]);
                                        out += op;
                                        from = From::Output(out - dist);
                                    }
                                }
                                match from {
                                    From::Window(at) => {
                                        output[out..out + len]
                                            .copy_from_slice(&window[at..at + len]);
                                    }
                                    From::Output(at) => copy_match(output, at, out, len),
                                }
                                out += len;
                            } else {
                                copy_match(output, out - dist, out, len);
                                out += len;
                            }
                            break;
                        } else if op & 64 == 0 {
                            here = dcode[usize::from(here.val) + low_bits!(op) as usize];
                        } else {
                            stop = Some((Mode::Bad, "invalid distance code"));
                            break 'decode;
                        }
                    }
                } else if op & 64 == 0 {
                    here = lcode[usize::from(here.val) + low_bits!(op) as usize];
                    continue 'dolen;
                } else if op & 32 != 0 {
                    stop = Some((Mode::Type, ""));
                    break 'decode;
                } else {
                    stop = Some((Mode::Bad, "invalid literal/length code"));
                    break 'decode;
                }
                break;
            }
            if !(inp < last && out < end) {
                break;
            }
        }

        let len = b >> 3;
        inp -= len as usize;
        b -= len << 3;
        h &= (1u64 << b) - 1;

        *next = inp;
        *put = out;
        *hold = h;
        *bits = b;
        if let Some((mode, msg)) = stop {
            self.mode = mode;
            self.msg = msg;
        }
    }
}
