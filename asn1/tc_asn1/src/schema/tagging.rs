use crate::{Asn1Error, Encode, EncodeContent, EncodeTagged, EncodingOptions};

pub struct Explicit<'a> {
    tag: &'a [u8],
    inner: &'a dyn Encode,
}
impl<'a> Explicit<'a> {
    pub fn new(tag: &'a [u8], inner: &'a dyn Encode) -> Self {
        debug_assert!(
            tag.first().is_some_and(|b| b & 0x20 != 0),
            "explicit tag must be constructed"
        );
        Self { tag, inner }
    }
}
impl EncodeContent for Explicit<'_> {
    /// 內層完整 TLV 的長度。變動時間：分支只依編碼結構。
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.inner.encoded_len(rules)
    }

    /// 寫出內層完整 TLV。變動時間：分支只依編碼結構。
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let len = crate::EncodeContent::content_len(self, rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        self.inner.encode(rules, out)
    }
}

impl EncodeTagged for Explicit<'_> {}

impl Encode for Explicit<'_> {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        EncodeTagged::encoded_len_tagged(self, self.tag, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, self.tag, rules, out)
    }
}


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
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.inner.content_len(rules)
    }

    /// 保留內層內容。變動時間：分支只依編碼結構。
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let len = crate::EncodeContent::content_len(self, rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        self.inner.encode_content(rules, out)
    }
}

impl EncodeTagged for Implicit<'_> {
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        self.inner.encoded_len_tagged(tag, rules)
    }

    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        self.inner.encode_tagged(tag, rules, out)
    }
}

impl Encode for Implicit<'_> {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, self.tag, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, self.tag, rules, out)
    }
}
