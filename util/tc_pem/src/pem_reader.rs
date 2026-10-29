use std::io::{self, BufRead};

use tc_encoders::{Encoder, EncoderError, base64};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::{PemHeader, PemObject};

const LINE_LENGTH: usize = 64;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// 解碼內文；失敗時清掉已寫出的部分，成功時清掉多配置的尾端。
fn decode(payload: &[u8]) -> Result<Vec<u8>, EncoderError> {
    let mut out = vec![0; base64::DEFAULT.decoded_len(payload.len())];
    match base64::DEFAULT.decode(payload, &mut out) {
        Ok(len) => {
            out[len..].zeroize();
            out.truncate(len);
            Ok(out)
        }
        Err(error) => {
            out.zeroize();
            Err(error)
        }
    }
}

/// 從 `BufRead` 逐一讀出 PEM 物件，對應 BC 的 `PemReader`。
///
/// `BEGIN` 之前的文字會略過；換行可以是 LF 或 CRLF。暫存的內文在 drop 時清除。
pub struct PemReader<R: BufRead> {
    reader: R,
    buffer: Zeroizing<Vec<u8>>,
    pushback: Zeroizing<Vec<Option<u8>>>,
}

impl<R: BufRead> PemReader<R> {
    /// 常數時間：不讀任何資料。
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Zeroizing::new(Vec::new()),
            pushback: Zeroizing::new(Vec::new()),
        }
    }

    /// 回傳底下的 `R`。
    /// 常數時間：不讀任何資料。
    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// 交回底下的 `R`；已讀出但還沒用到的字元就此丟棄。
    /// 常數時間：不讀任何資料。
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// 讀下一個 PEM 物件；找不到下一個 `-` 時回傳 `None`。外框或標頭不對、內文不是
    /// base64 時回傳 `InvalidData`。
    /// 變動時間：依外框與標頭這些公開值分支；內文逐字元只分辨空白與 `-`，不分辨
    /// base64 字元，base64 解碼也不依字元值分支或查表。
    pub fn read_pem_object(&mut self) -> io::Result<Option<PemObject>> {
        loop {
            if !self.seek_dash()? {
                return Ok(None);
            }
            if !self.consume_dash()? {
                return Err(invalid("no data after consuming leading dashes"));
            }
            self.skip_white_space()?;
            if self.expect(b"BEGIN")? {
                break;
            }
        }

        self.skip_white_space()?;
        if !self.buffer_until_stop_char(b'-', false)? {
            return Err(invalid("ran out of data before consuming type"));
        }
        let pem_type = self.buffered_string();
        let pem_type = pem_type.trim();
        if !self.consume_dash()? {
            return Err(invalid("ran out of data consuming header"));
        }
        self.skip_white_space()?;

        let mut headers = Vec::new();
        while self.seek_colon(LINE_LENGTH)? {
            if !self.buffer_until_stop_char(b':', false)? {
                return Err(invalid("ran out of data reading header key value"));
            }
            let key = self.buffered_string().trim().to_owned();
            if self.next_char()? != Some(b':') {
                return Err(invalid("expected colon"));
            }
            if !self.buffer_until_stop_char(b'\n', false)? {
                return Err(invalid("ran out of data before consuming header value"));
            }
            self.skip_white_space()?;
            let value = self.buffered_string().trim().to_owned();
            headers.push(PemHeader::new(key, value));
        }

        self.skip_white_space()?;
        if !self.buffer_until_stop_char(b'-', true)? {
            self.buffer.zeroize();
            return Err(invalid("ran out of data before consuming payload"));
        }
        let payload = Zeroizing::new(std::mem::take(&mut *self.buffer));

        if !self.seek_dash()? {
            return Err(invalid("did not find leading '-'"));
        }
        if !self.consume_dash()? {
            return Err(invalid("no data after consuming trailing dashes"));
        }
        let end = format!("END {pem_type}");
        if !self.expect(end.as_bytes())? {
            return Err(invalid(format!("{end} was not found.")));
        }
        if !self.seek_dash()? {
            return Err(invalid("did not find ending '-'"));
        }
        self.consume_dash()?;

        let content = decode(&payload).map_err(|e| invalid(format!("malformed PEM data: {e}")))?;
        Ok(Some(
            PemObject::new(pem_type, content).with_headers(headers),
        ))
    }

    fn buffered_string(&mut self) -> String {
        let bytes = std::mem::take(&mut *self.buffer);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn seek_dash(&mut self) -> io::Result<bool> {
        let c = loop {
            match self.next_char()? {
                Some(b'-') => break Some(b'-'),
                Some(_) => {}
                None => break None,
            }
        };
        self.pushback.push(c);
        Ok(c.is_some())
    }

    /// 往後看至多 `up_to + 1` 個字元找 `:`，看過的字元全部推回。
    fn seek_colon(&mut self, up_to: usize) -> io::Result<bool> {
        let mut read = Zeroizing::new([None; LINE_LENGTH + 1]);
        let mut len = 0;
        let mut found = false;
        while len <= up_to {
            let c = self.next_char()?;
            read[len] = c;
            len += 1;
            if c == Some(b':') {
                found = true;
                break;
            }
            if c.is_none() {
                break;
            }
        }
        for &c in read[..len].iter().rev() {
            self.pushback.push(c);
        }
        Ok(found)
    }

    fn consume_dash(&mut self) -> io::Result<bool> {
        let c = loop {
            match self.next_char()? {
                Some(b'-') => {}
                c => break c,
            }
        };
        self.pushback.push(c);
        Ok(c.is_some())
    }

    fn skip_white_space(&mut self) -> io::Result<()> {
        let c = loop {
            match self.next_char()? {
                Some(c) if c <= b' ' => {}
                c => break c,
            }
        };
        self.pushback.push(c);
        Ok(())
    }

    fn expect(&mut self, value: &[u8]) -> io::Result<bool> {
        for &expected in value {
            if self.next_char()? != Some(expected) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn buffer_until_stop_char(&mut self, stop: u8, skip_white_space: bool) -> io::Result<bool> {
        loop {
            match self.next_char()? {
                None => return Ok(false),
                Some(c) if skip_white_space && c <= b' ' => {}
                Some(c) if c == stop => {
                    self.pushback.push(Some(c));
                    return Ok(true);
                }
                Some(c) => self.buffer.push(c),
            }
        }
    }

    fn next_char(&mut self) -> io::Result<Option<u8>> {
        if let Some(c) = self.pushback.pop() {
            return Ok(c);
        }
        loop {
            match self.reader.fill_buf() {
                Ok(buf) => {
                    let c = buf.first().copied();
                    if c.is_some() {
                        self.reader.consume(1);
                    }
                    return Ok(c);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}
