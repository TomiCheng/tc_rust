//! 對應 C 的 `z_stream` 呼叫介面：一次 `deflate`／`inflate` 的進度與回傳碼。

use std::io;

use crate::constants::FlushMode;
use crate::deflate::DeflateState;
use crate::inflate::InflateState;

/// zlib 的回傳碼；`Z_MEM_ERROR` 在這個移植裡不會發生。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Ok,
    StreamEnd,
    NeedDict,
    BufError,
    DataError(&'static str),
    StreamError,
}

pub(crate) struct Step {
    pub(crate) read: usize,
    pub(crate) written: usize,
    pub(crate) status: Status,
}

pub(crate) enum Engine {
    Deflate(Box<DeflateState>),
    Inflate(Box<InflateState>),
}

impl Engine {
    pub(crate) fn run(&mut self, input: &[u8], output: &mut [u8], flush: FlushMode) -> Step {
        match self {
            Engine::Deflate(state) => state.deflate(input, output, flush),
            Engine::Inflate(state) => state.inflate(input, output, flush),
        }
    }
}

/// 把錯誤碼轉成 `io::Error`；`Ok`、`StreamEnd`、`BufError` 由呼叫端自己判斷。
pub(crate) fn data_error(status: Status) -> io::Result<()> {
    match status {
        Status::DataError(msg) => Err(io::Error::new(io::ErrorKind::InvalidData, msg)),
        Status::NeedDict => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stream needs a preset dictionary",
        )),
        Status::StreamError => Err(io::Error::other("zlib stream used after it finished")),
        Status::Ok | Status::StreamEnd | Status::BufError => Ok(()),
    }
}

pub(crate) fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "truncated zlib stream")
}

pub(crate) fn stalled() -> io::Error {
    io::Error::other("zlib made no progress")
}
