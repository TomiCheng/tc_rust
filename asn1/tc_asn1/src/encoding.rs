//! Shared TLV encoding and length-field helpers.

use crate::{Asn1Error, EncodeContent, EncodingOptions, EncodingType};

/// CER 與 BER 不定長選項對每一層 constructed 使用不定長。常數時間。
const fn uses_indefinite(tag: &[u8], rules: &EncodingOptions) -> bool {
    matches!(
        rules.encoding_type(),
        EncodingType::Cer | EncodingType::Ber(crate::LengthForm::Indefinite)
    ) && tag[0] & 0x20 != 0
}

/// Length of an ordinary TLV. Variable time: branches only on the encoding structure.
pub(crate) fn default_encoded_len<T: EncodeContent + ?Sized>(
    value: &T,
    tag: &[u8],
    rules: &EncodingOptions,
) -> usize {
    let len = value.content_len(rules);
    tag.len()
        + if uses_indefinite(tag, rules) {
            1 + len + 2
        } else {
            len_octets(len) + len
        }
}

/// Writes an ordinary TLV. Variable time: branches only on the encoding structure.
pub(crate) fn default_encode<T: EncodeContent + ?Sized>(
    value: &T,
    tag: &[u8],
    rules: &EncodingOptions,
    out: &mut [u8],
) -> Result<usize, Asn1Error> {
    let content_len = value.content_len(rules);
    let indefinite = uses_indefinite(tag, rules);
    let total = tag.len()
        + if indefinite {
            1 + content_len + 2
        } else {
            len_octets(content_len) + content_len
        };
    let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
    out[..tag.len()].copy_from_slice(tag);
    let mut at = tag.len();
    if indefinite {
        out[at] = 0x80;
        at += 1;
    } else {
        at += write_len(content_len, &mut out[at..]);
    }
    let written = value.encode_content(rules, &mut out[at..at + content_len])?;
    debug_assert_eq!(
        written, content_len,
        "content_len and encode_content disagree"
    );
    if indefinite {
        out[at + content_len..].fill(0);
    }
    Ok(total)
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
