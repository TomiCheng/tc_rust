use alloc::vec::Vec;

use crate::{EncodingOptions, EncodingType};
use crate::Asn1Error;

pub trait EncodeContent {
    fn encode_content_to_vec(&self, rules: &EncodingOptions) -> Result<Vec<u8>, Asn1Error> {
        let mut out = alloc::vec![0; self.content_len(rules)];
        let written = self.encode_content(rules, &mut out)?;
        debug_assert_eq!(
            written,
            out.len(),
            "content_len and encode_content disagree"
        );
        Ok(out)
    }

    fn content_len(&self, rules: &EncodingOptions) -> usize;

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error>;
}

pub trait EncodeTagged: EncodeContent {
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        default_encoded_len(self, tag, rules)
    }

    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        default_encode(self, tag, rules, out)
    }
}

pub trait Encode: EncodeTagged {
    fn encode_to_vec(&self, rules: &EncodingOptions) -> Result<Vec<u8>, Asn1Error> {
        let mut out = alloc::vec![0; self.encoded_len(rules)];
        let written = self.encode(rules, &mut out)?;
        debug_assert_eq!(written, out.len(), "encoded_len and encode disagree");
        Ok(out)
    }

    fn encoded_len(&self, rules: &EncodingOptions) -> usize;

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error>;
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

const fn uses_indefinite(tag: &[u8], rules: &EncodingOptions) -> bool {
    matches!(
        rules.encoding_type(),
        EncodingType::Cer | EncodingType::Ber(crate::LengthForm::Indefinite)
    ) && tag[0] & 0x20 != 0
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

pub(crate) const fn len_octets(length: usize) -> usize {
    if length < 0x80 {
        1
    } else {
        1 + (usize::BITS - length.leading_zeros()).div_ceil(8) as usize
    }
}

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