//! 寫出的契約。object-safe：只有方法，沒有關聯常數，才能放進 `dyn`。

use alloc::boxed::Box;

use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;

pub trait Encode {
    /// 沒有被重新標記時的識別位元組。
    fn tag(&self) -> &[u8];

    /// 內容的位元組數，不含表頭。
    fn content_len(&self, rules: EncodingType) -> usize;

    /// 只寫內容，回傳寫入的位元組數。呼叫端保證 `out` 至少 `content_len` 長。
    fn encode_content(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error>;

    /// 完整 TLV 的位元組數。
    fn encoded_len(&self, rules: EncodingType) -> usize {
        let content_len = self.content_len(rules);
        self.tag().len() + len_octets(content_len) + content_len
    }

    /// 用自己的 tag 寫完整的 TLV。
    fn encode(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(self.tag(), rules, out)
    }

    /// 用呼叫端給的 tag 時完整 TLV 的位元組數。
    fn encoded_len_tagged(&self, tag: &[u8], rules: EncodingType) -> usize {
        let content_len = self.content_len(rules);
        tag.len() + len_octets(content_len) + content_len
    }

    /// 用呼叫端給的 tag 寫完整的 TLV —— IMPLICIT 走這裡。
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: EncodingType,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        let content_len = self.content_len(rules);
        let total = tag.len() + len_octets(content_len) + content_len;
        let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;

        out[..tag.len()].copy_from_slice(tag);
        let mut at = tag.len();
        at += write_len(content_len, &mut out[at..]);
        let written = self.encode_content(rules, &mut out[at..])?;
        debug_assert_eq!(written, content_len, "content_len 與 encode_content 不一致");
        Ok(total)
    }
}

impl<T: ?Sized + Encode> Encode for Box<T> {
    fn tag(&self) -> &[u8] {
        (**self).tag()
    }
    fn content_len(&self, rules: EncodingType) -> usize {
        (**self).content_len(rules)
    }
    fn encode_content(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        (**self).encode_content(rules, out)
    }
}

/// 長度欄位佔幾個位元組。永遠是最短的定長形式。
pub(crate) const fn len_octets(length: usize) -> usize {
    if length < 0x80 {
        1
    } else {
        1 + (usize::BITS - length.leading_zeros()).div_ceil(8) as usize
    }
}

/// 寫出長度欄位，回傳寫入的位元組數。呼叫端保證 `out` 夠長。
pub(crate) fn write_len(length: usize, out: &mut [u8]) -> usize {
    if length < 0x80 {
        out[0] = length as u8;
        return 1;
    }
    let count = len_octets(length) - 1;
    out[0] = 0x80 | count as u8;
    for (index, slot) in out[1..=count].iter_mut().enumerate() {
        *slot = (length >> (8 * (count - 1 - index))) as u8;
    }
    1 + count
}
