use std::io::{self, Write};

use tc_encoders::{Encoder, base64};
use tc_zeroize::Zeroizing;

use crate::{PemObject, PemObjectGenerator};

const LINE_LENGTH: usize = 64;

fn has_line_break(s: &str) -> bool {
    s.contains(['\r', '\n'])
}

/// 把 PEM 物件寫進 `Write`，對應 BC 的 `PemWriter`。
///
/// 換行固定寫 LF；BC 用 `Environment.NewLine`，在 Windows 上是 CRLF。
pub struct PemWriter<W: Write> {
    writer: W,
}

impl<W: Write> PemWriter<W> {
    /// 常數時間：不寫任何資料。
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// 回傳底下的 `W`。
    /// 常數時間：不寫任何資料。
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// 交回底下的 `W`。
    /// 常數時間：不寫任何資料。
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// [`write_object`](Self::write_object) 寫出 `obj` 的位元組數。
    /// 常數時間：只看長度，不看內容。
    pub fn get_output_size(&self, obj: &PemObject) -> usize {
        let nl = 1;
        let mut size = 2 * (obj.pem_type().len() + 10 + nl) + 6 + 4;
        if !obj.headers().is_empty() {
            for header in obj.headers() {
                size += header.name().len() + ": ".len() + header.value().len() + nl;
            }
            size += nl;
        }
        let data_len = obj.content().len().div_ceil(3) * 4;
        size + data_len + data_len.div_ceil(LINE_LENGTH) * nl
    }

    /// 寫出 `generator` 產生的物件：外框、標頭、空行，再把內文每 64 個字元一行寫出。
    /// 標頭含 CR 或 LF 時回傳 `InvalidInput`，不寫出任何東西。
    /// 變動時間：外框與標頭依長度輸出，只能是公開值；內文的 base64 編碼不依位元組值
    /// 分支或查表。
    pub fn write_object(&mut self, generator: &impl PemObjectGenerator) -> io::Result<()> {
        let obj = generator.generate()?;
        if obj
            .headers()
            .iter()
            .any(|header| has_line_break(header.name()) || has_line_break(header.value()))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PEM header must not contain CR/LF",
            ));
        }

        writeln!(self.writer, "-----BEGIN {}-----", obj.pem_type())?;
        if !obj.headers().is_empty() {
            for header in obj.headers() {
                writeln!(self.writer, "{}: {}", header.name(), header.value())?;
            }
            writeln!(self.writer)?;
        }
        self.write_encoded(obj.content())?;
        writeln!(self.writer, "-----END {}-----", obj.pem_type())
    }

    fn write_encoded(&mut self, content: &[u8]) -> io::Result<()> {
        let mut line = Zeroizing::new([0u8; LINE_LENGTH + 1]);
        for chunk in content.chunks(LINE_LENGTH / 4 * 3) {
            let len = base64::DEFAULT
                .encode(chunk, &mut line[..])
                .expect("a line holds 48 encoded bytes");
            line[len] = b'\n';
            self.writer.write_all(&line[..=len])?;
        }
        Ok(())
    }
}
