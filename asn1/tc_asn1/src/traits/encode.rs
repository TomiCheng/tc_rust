//! 寫出的契約。object-safe：只有方法，沒有關聯常數，才能放進 `dyn`。

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;

pub trait Encode {
    /// 配置剛好大小的 Vec 並寫入完整 TLV。變動時間：分支只依編碼結構。
    ///
    /// 對照 bc 的 `GetEncoded(encoding)`；編碼失敗時傳回錯誤，不轉成 panic。
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Asn1Boolean, Encode, EncodingType};
    /// assert_eq!(Asn1Boolean(true).encode_to_vec(EncodingType::Der)?, [1, 1, 255]);
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    fn encode_to_vec(&self, rules: EncodingType) -> Result<Vec<u8>, Asn1Error> {
        let mut out = alloc::vec![0; self.encoded_len(rules)];
        let written = self.encode(rules, &mut out)?;
        debug_assert_eq!(written, out.len(), "encoded_len 與 encode 不一致");
        Ok(out)
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Asn1Boolean, Asn1Object, Asn1Tagged, Decode, Depth};
    use alloc::vec;

    #[test]
    fn vector_encoding_matches_manual_encoding_and_remains_available_through_trait_objects() {
        let value: &dyn Encode = &Asn1Boolean(true);
        assert_eq!(value.encode_to_vec(EncodingType::Der).unwrap(), [1, 1, 255]);
        let tree = Asn1Object::Sequence(vec![Asn1Object::Sequence(vec![
            Asn1Tagged::constructed(&[0x80], vec![Asn1Boolean(true).into()])
                .unwrap()
                .into(),
        ])]);
        for rules in [EncodingType::Der, EncodingType::Ber] {
            let mut out = vec![0; tree.encoded_len(rules)];
            let written = tree.encode(rules, &mut out).unwrap();
            assert_eq!(written, out.len());
            assert_eq!(tree.encode_to_vec(rules).unwrap(), out);
        }
    }

    #[test]
    fn vector_encoding_preserves_unknown_headers_and_returns_sorting_errors() {
        let tree = Asn1Object::try_decode_exact(&[0x1f, 0x25, 0x81, 0], Depth::DEFAULT).unwrap();
        assert_eq!(
            tree.encode_to_vec(EncodingType::Der).unwrap(),
            [0x1f, 0x25, 0x81, 0]
        );
        let value: &dyn Encode = &tree;
        assert_eq!(
            value.encode_to_vec(EncodingType::Der).unwrap(),
            [0x1f, 0x25, 0x81, 0]
        );
        let input = [
            0x1f, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0,
        ];
        let tree = Asn1Object::Set(vec![
            Asn1Object::try_decode_exact(&input, Depth::DEFAULT).unwrap(),
        ]);
        assert_eq!(
            tree.encode_to_vec(EncodingType::Der),
            Err(Asn1Error::TagOverflow)
        );
        assert!(tree.encode_to_vec(EncodingType::Ber).is_ok());
    }
}
