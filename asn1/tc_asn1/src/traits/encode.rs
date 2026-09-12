//! 寫出的契約。object-safe：只有方法，沒有關聯常數，才能放進 `dyn`。

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::encoding_options::EncodingOptions;
use crate::error::Asn1Error;

pub trait Encode {
    /// 配置剛好大小的 Vec 並寫入完整 TLV。變動時間：分支只依編碼結構。
    ///
    /// 對照 bc 的 `GetEncoded(encoding)`；編碼失敗時傳回錯誤，不轉成 panic。
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Asn1Boolean, Encode, EncodingOptions};
    /// assert_eq!(Asn1Boolean(true).encode_to_vec(EncodingOptions::Der)?, [1, 1, 255]);
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    fn encode_to_vec(&self, rules: EncodingOptions) -> Result<Vec<u8>, Asn1Error> {
        let mut out = alloc::vec![0; self.encoded_len(rules)];
        let written = self.encode(rules, &mut out)?;
        debug_assert_eq!(written, out.len(), "encoded_len 與 encode 不一致");
        Ok(out)
    }

    /// 沒有被重新標記時的識別位元組。
    fn tag(&self) -> &[u8];

    /// 內容的位元組數，不含表頭。
    fn content_len(&self, rules: EncodingOptions) -> usize;

    /// 只寫內容，回傳寫入的位元組數。呼叫端保證 `out` 至少 `content_len` 長。
    fn encode_content(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error>;

    /// 完整 TLV 的位元組數。
    fn encoded_len(&self, rules: EncodingOptions) -> usize {
        self.encoded_len_tagged(self.tag(), rules)
    }

    /// 用自己的 tag 寫完整的 TLV。
    fn encode(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(self.tag(), rules, out)
    }

    /// 用呼叫端給的 tag 時完整 TLV 的位元組數。
    fn encoded_len_tagged(&self, tag: &[u8], rules: EncodingOptions) -> usize {
        default_encoded_len(self, tag, rules)
    }

    /// 用呼叫端給的 tag 寫完整的 TLV —— IMPLICIT 走這裡。
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        default_encode(self, tag, rules, out)
    }
}

/// CER 與 BER 不定長選項對每一層 constructed 使用不定長。常數時間。
pub(crate) const fn uses_indefinite(tag: &[u8], rules: EncodingOptions) -> bool {
    matches!(
        rules,
        EncodingOptions::Cer | EncodingOptions::Ber(crate::LengthForm::Indefinite)
    ) && tag[0] & 0x20 != 0
}

/// Length of an ordinary TLV. Variable time: branches only on the encoding structure.
pub(crate) fn default_encoded_len<T: Encode + ?Sized>(
    value: &T,
    tag: &[u8],
    rules: EncodingOptions,
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
pub(crate) fn default_encode<T: Encode + ?Sized>(
    value: &T,
    tag: &[u8],
    rules: EncodingOptions,
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

impl<T: ?Sized + Encode> Encode for Box<T> {
    fn encoded_len(&self, rules: EncodingOptions) -> usize {
        (**self).encoded_len(rules)
    }
    fn encode(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        (**self).encode(rules, out)
    }
    fn encoded_len_tagged(&self, tag: &[u8], rules: EncodingOptions) -> usize {
        (**self).encoded_len_tagged(tag, rules)
    }
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        (**self).encode_tagged(tag, rules, out)
    }
    fn tag(&self) -> &[u8] {
        (**self).tag()
    }
    fn content_len(&self, rules: EncodingOptions) -> usize {
        (**self).content_len(rules)
    }
    fn encode_content(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
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
    fn indefinite_ber_preserves_nested_set_order_and_accounts_for_every_end_marker() {
        use crate::{Asn1Integer, LengthForm};
        let options = EncodingOptions::Ber(LengthForm::Indefinite);
        let set = Asn1Object::Set(vec![
            Asn1Integer::from(5_u8).into(),
            Asn1Integer::from(3_u8).into(),
        ]);
        for (tree, expected) in [
            (Asn1Object::Set(vec![]), vec![0x31, 0x80, 0, 0]),
            (set.clone(), vec![0x31, 0x80, 2, 1, 5, 2, 1, 3, 0, 0]),
            (
                Asn1Object::Sequence(vec![set]),
                vec![0x30, 0x80, 0x31, 0x80, 2, 1, 5, 2, 1, 3, 0, 0, 0, 0],
            ),
        ] {
            let boxed: Box<dyn Encode> = Box::new(tree.clone());
            for encoder in [&tree as &dyn Encode, boxed.as_ref()] {
                assert_eq!(encoder.encoded_len(options), expected.len());
                assert_eq!(encoder.encode_to_vec(options).unwrap(), expected);
                let mut out = vec![0xaa; expected.len() + 3];
                assert_eq!(encoder.encode(options, &mut out).unwrap(), expected.len());
                assert_eq!(&out[..expected.len()], expected);
                assert_eq!(&out[expected.len()..], &[0xaa; 3]);
                assert_eq!(
                    encoder.encode(options, &mut vec![0; expected.len() - 1]),
                    Err(Asn1Error::BufferTooSmall)
                );
            }
            assert_eq!(
                Asn1Object::try_decode_exact(&expected, Depth::DEFAULT).unwrap(),
                tree
            );
        }
    }

    #[test]
    fn indefinite_ber_does_not_apply_canonical_set_of_sorting() {
        use crate::{Asn1SetOf, LengthForm};
        let set = Asn1SetOf::from(vec![Asn1Boolean(true), Asn1Boolean(false)]);
        for (options, expected) in [
            (
                EncodingOptions::Ber(LengthForm::Definite),
                vec![0x31, 6, 1, 1, 255, 1, 1, 0],
            ),
            (
                EncodingOptions::Ber(LengthForm::Indefinite),
                vec![0x31, 0x80, 1, 1, 255, 1, 1, 0, 0, 0],
            ),
            (
                EncodingOptions::Cer,
                vec![0x31, 0x80, 1, 1, 0, 1, 1, 255, 0, 0],
            ),
            (EncodingOptions::Der, vec![0x31, 6, 1, 1, 0, 1, 1, 255]),
        ] {
            assert_eq!(set.encoded_len(options), expected.len());
            assert_eq!(set.encode_to_vec(options).unwrap(), expected);
            if !options.is_canonical() {
                assert_eq!(
                    Asn1SetOf::<Asn1Boolean>::try_decode_exact(&expected, Depth::DEFAULT).unwrap(),
                    set
                );
            }
        }
    }

    #[test]
    fn indefinite_ber_keeps_long_strings_primitive_and_only_wraps_constructed_tags() {
        use crate::{
            Asn1BitString, Asn1OctetString, Asn1Utf8String, Explicit, Implicit, LengthForm,
        };
        let options = EncodingOptions::Ber(LengthForm::Indefinite);
        let octets = Asn1OctetString::new(&vec![0xaa; 1001]);
        let bits = Asn1BitString::from_bytes(&vec![0xaa; 1001]);
        let text = Asn1Utf8String::new(&"a".repeat(1001));
        for value in [&octets as &dyn Encode, &bits, &text] {
            let wire = value.encode_to_vec(options).unwrap();
            assert_eq!(
                wire,
                value
                    .encode_to_vec(EncodingOptions::Ber(LengthForm::Definite))
                    .unwrap()
            );
            assert_eq!(wire.len(), value.encoded_len(options));
            assert_eq!(wire[0] & 0x20, 0);
        }
        let sequence = Asn1Object::Sequence(vec![Asn1Boolean(true).into()]);
        for (value, expected) in [
            (
                Explicit::new(&[0xa0], &sequence)
                    .encode_to_vec(options)
                    .unwrap(),
                vec![0xa0, 0x80, 0x30, 0x80, 1, 1, 255, 0, 0, 0, 0],
            ),
            (
                Implicit::new(&[0xbf, 0x81, 0], &sequence)
                    .encode_to_vec(options)
                    .unwrap(),
                vec![0xbf, 0x81, 0, 0x80, 1, 1, 255, 0, 0],
            ),
            (
                Implicit::new(&[0x80], &Asn1Boolean(true))
                    .encode_to_vec(options)
                    .unwrap(),
                vec![0x80, 1, 255],
            ),
        ] {
            assert_eq!(value, expected);
        }
    }

    #[test]
    fn cer_constructed_values_use_indefinite_lengths_and_sorted_sets() {
        use crate::{Asn1Integer, Explicit};
        let sequence =
            Asn1Object::Sequence(vec![Asn1Integer::from(42_u8).into(), Asn1Object::Null]);
        let set = Asn1Object::Set(vec![
            Asn1Integer::from(5_u8).into(),
            Asn1Integer::from(3_u8).into(),
        ]);
        for (value, expected) in [
            (sequence, &[0x30, 0x80, 2, 1, 42, 5, 0, 0, 0][..]),
            (set, &[0x31, 0x80, 2, 1, 3, 2, 1, 5, 0, 0][..]),
        ] {
            assert_eq!(value.encoded_len(EncodingOptions::Cer), expected.len());
            assert_eq!(value.encode_to_vec(EncodingOptions::Cer).unwrap(), expected);
            assert_eq!(
                Asn1Object::try_decode_exact(expected, Depth::DEFAULT)
                    .unwrap()
                    .encode_to_vec(EncodingOptions::Cer)
                    .unwrap(),
                expected
            );
            assert_eq!(
                value.encode(EncodingOptions::Cer, &mut vec![0; expected.len() - 1]),
                Err(Asn1Error::BufferTooSmall)
            );
            let mut out = vec![0xaa; expected.len() + 3];
            assert_eq!(
                value.encode(EncodingOptions::Cer, &mut out).unwrap(),
                expected.len()
            );
            assert_eq!(&out[expected.len()..], &[0xaa; 3]);
        }
        let integer = Asn1Integer::from(2_u8);
        assert_eq!(
            Explicit::new(&[0xa0], &integer)
                .encode_to_vec(EncodingOptions::Cer)
                .unwrap(),
            [0xa0, 0x80, 2, 1, 2, 0, 0]
        );
    }

    #[test]
    fn cer_preserves_raw_unknown_encodings() {
        use crate::Asn1Any;
        let input = [0x1f, 0x25, 0x81, 0];
        assert_eq!(
            Asn1Any::try_decode_exact(&input, Depth::DEFAULT)
                .unwrap()
                .encode_to_vec(EncodingOptions::Cer)
                .unwrap(),
            input
        );
        assert_eq!(
            Asn1Object::try_decode_exact(&input, Depth::DEFAULT)
                .unwrap()
                .encode_to_vec(EncodingOptions::Cer)
                .unwrap(),
            input
        );
    }

    #[test]
    fn vector_encoding_matches_manual_encoding_and_remains_available_through_trait_objects() {
        let value: &dyn Encode = &Asn1Boolean(true);
        assert_eq!(
            value.encode_to_vec(EncodingOptions::Der).unwrap(),
            [1, 1, 255]
        );
        let tree = Asn1Object::Sequence(vec![Asn1Object::Sequence(vec![
            Asn1Tagged::constructed(&[0x80], vec![Asn1Boolean(true).into()])
                .unwrap()
                .into(),
        ])]);
        for rules in [
            EncodingOptions::Der,
            EncodingOptions::Ber(crate::LengthForm::Definite),
        ] {
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
            tree.encode_to_vec(EncodingOptions::Der).unwrap(),
            [0x1f, 0x25, 0x81, 0]
        );
        let value: &dyn Encode = &tree;
        assert_eq!(
            value.encode_to_vec(EncodingOptions::Der).unwrap(),
            [0x1f, 0x25, 0x81, 0]
        );
        let input = [
            0x1f, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0,
        ];
        let tree = Asn1Object::Set(vec![
            Asn1Object::try_decode_exact(&input, Depth::DEFAULT).unwrap(),
        ]);
        assert_eq!(
            tree.encode_to_vec(EncodingOptions::Der),
            Err(Asn1Error::TagOverflow)
        );
        assert!(
            tree.encode_to_vec(EncodingOptions::Ber(crate::LengthForm::Definite))
                .is_ok()
        );
    }
}
