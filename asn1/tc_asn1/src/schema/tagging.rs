//! 以借用值組合 EXPLICIT 與 IMPLICIT 標記。
use crate::{Asn1Error, Encode, EncodingOptions};

/// EXPLICIT 包裝；tag 必須是完整且合法的 constructed 識別位元組。
/// 呼叫端負責標記，與 [`crate::EncodeTagged::encode_tagged`] 的契約相同。
///
/// # Examples
/// ```
/// use tc_asn1::{Asn1Integer, Encode, EncodingOptions, Explicit};
/// let number = Asn1Integer::from(2_u8);
/// let tagged = Explicit::new(&[0xA0], &number);
/// let mut out = [0; 5];
/// tagged.encode(EncodingOptions::Der, &mut out)?;
/// assert_eq!(out, [0xA0, 3, 2, 1, 2]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub struct Explicit<'a> {
    tag: &'a [u8],
    inner: &'a dyn Encode,
}
impl<'a> Explicit<'a> {
    /// 借用 tag 與內層值；debug 建置檢查 constructed 位。
    /// 變動時間契約：分支只依編碼結構。
    pub fn new(tag: &'a [u8], inner: &'a dyn Encode) -> Self {
        debug_assert!(
            tag.first().is_some_and(|b| b & 0x20 != 0),
            "explicit tag must be constructed"
        );
        Self { tag, inner }
    }
}
impl crate::EncodeContent for Explicit<'_> {
    /// 內層完整 TLV 的長度。變動時間：分支只依編碼結構。
    fn content_len(&self, rules: EncodingOptions) -> usize {
        self.inner.encoded_len(rules)
    }

    /// 寫出內層完整 TLV。變動時間：分支只依編碼結構。
    fn encode_content(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let len = crate::EncodeContent::content_len(self, rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        self.inner.encode(rules, out)
    }
}

impl crate::EncodeTagged for Explicit<'_> {}

impl Encode for Explicit<'_> {
    fn encoded_len(&self, rules: EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, self.tag, rules)
    }

    fn encode(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, self.tag, rules, out)
    }
}

/// IMPLICIT 換 tag，保留原本的內容；呼叫端負責完整識別位元組與 constructed 位。
///
/// # Examples
/// ```
/// use tc_asn1::{Asn1Boolean, Encode, EncodingOptions, Implicit};
/// let tagged = Implicit::new(&[0x80], &Asn1Boolean(true));
/// let mut out = [0; 3];
/// tagged.encode(EncodingOptions::Der, &mut out)?;
/// assert_eq!(out, [0x80, 1, 0xFF]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub struct Implicit<'a> {
    tag: &'a [u8],
    inner: &'a dyn Encode,
}
impl<'a> Implicit<'a> {
    /// 借用替換 tag 與內層值。變動時間契約：分支只依編碼結構。
    pub fn new(tag: &'a [u8], inner: &'a dyn Encode) -> Self {
        Self { tag, inner }
    }
}
impl crate::EncodeContent for Implicit<'_> {
    /// 保留內層內容長度。變動時間：分支只依編碼結構。
    fn content_len(&self, rules: EncodingOptions) -> usize {
        self.inner.content_len(rules)
    }

    /// 保留內層內容。變動時間：分支只依編碼結構。
    fn encode_content(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let len = crate::EncodeContent::content_len(self, rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        self.inner.encode_content(rules, out)
    }
}

impl crate::EncodeTagged for Implicit<'_> {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len_tagged(&self, tag: &[u8], rules: EncodingOptions) -> usize {
        self.inner.encoded_len_tagged(tag, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        self.inner.encode_tagged(tag, rules, out)
    }
}

impl Encode for Implicit<'_> {
    fn encoded_len(&self, rules: EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, self.tag, rules)
    }

    fn encode(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, self.tag, rules, out)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Asn1Boolean, Asn1Integer, Asn1OctetString};
    #[test]
    fn explicit_tagging_wraps_the_entire_inner_tlv() {
        let number = Asn1Integer::from(2_u8);
        let value = Explicit::new(&[0xA0], &number);
        for rules in [
            EncodingOptions::Ber(crate::LengthForm::Definite),
            EncodingOptions::Der,
        ] {
            assert_eq!(value.encoded_len(rules), 5);
            let mut out = [0; 5];
            assert_eq!(value.encode(rules, &mut out), Ok(5));
            assert_eq!(out, [0xA0, 3, 2, 1, 2]);
            assert_eq!(
                value.encode(rules, &mut [0; 4]),
                Err(Asn1Error::BufferTooSmall)
            );
        }
    }
    #[test]
    fn implicit_tagging_replaces_only_the_identifier() {
        let value = Implicit::new(&[0x80], &Asn1Boolean(true));
        let mut out = [0; 3];
        value.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(out, [0x80, 1, 255]);
    }
    #[test]
    fn tagging_supports_high_tag_numbers_and_long_content_lengths() {
        let octets = Asn1OctetString::new(&[7; 128]);
        let explicit = Explicit::new(&[0xBF, 0x20], &octets);
        let mut out = alloc::vec![0;explicit.encoded_len(EncodingOptions::Der)];
        explicit.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(&out[..7], &[0xBF, 0x20, 0x81, 131, 4, 0x81, 128]);
        assert_eq!(out.len(), 135);
        let implicit = Implicit::new(&[0x9F, 0x20], &octets);
        let mut out = alloc::vec![0;implicit.encoded_len(EncodingOptions::Der)];
        implicit.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(&out[..4], &[0x9F, 0x20, 0x81, 128]);
        assert_eq!(out.len(), 132);
    }
}
