use alloc::vec::Vec;

use crate::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, DecodingOptions, Encode,
    EncodeContent, EncodeTagged, EncodingOptions,
};

/// A constructed encoding: an identifier and a series of `T` values.
///
/// This is the one mechanism behind SEQUENCE OF, SET OF and the constructed
/// string forms. The identifier is whatever the value was built or read with
/// (`30` for SEQUENCE OF, `31` for SET OF, `24` for a segmented OCTET STRING,
/// `A0` for `[0] IMPLICIT`, ...); decoding accepts any constructed identifier
/// and keeps it, so checking that it is the expected one is the caller's job.
/// With `T = Asn1Any` the elements are kept as raw TLVs.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Constructed<T> {
    tag: Vec<u8>,
    items: Vec<T>,
}

impl<T> Asn1Constructed<T> {
    /// `tag` is a complete identifier; its constructed bit is set if missing.
    pub fn new(tag: &[u8], items: Vec<T>) -> Self {
        let mut tag = tag.to_vec();
        if let Some(first) = tag.first_mut() {
            *first |= 0x20;
        }
        Self { tag, items }
    }

    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    pub fn items(&self) -> &[T] {
        &self.items
    }

    pub fn into_items(self) -> Vec<T> {
        self.items
    }
}

impl<T: DecodeInner> DecodeInner for Asn1Constructed<T> {
    /// Any constructed identifier is accepted and kept; each child is one `T`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        if !element.is_constructed() {
            return Err(Asn1Error::UnexpectedTag);
        }
        let mut children = element.children(context)?;
        let mut items = Vec::new();
        while let Some(child) = children.next() {
            let child = child?;
            let (used, item) = T::decode_inner(child.raw(), children.context())?;
            debug_assert_eq!(used, child.total_len(), "child length disagrees");
            items.push(item);
        }
        Ok((
            element.total_len(),
            Self {
                tag: element.tag().to_vec(),
                items,
            },
        ))
    }

    fn decode_inner_der(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse_der(buff, context)?;
        if !element.is_constructed() {
            return Err(Asn1Error::UnexpectedTag);
        }
        let mut children = element.children(context)?;
        let mut items = Vec::new();
        while let Some(child) = children.next() {
            let child = child?;
            let (used, item) = T::decode_inner_der(child.raw(), children.context())?;
            debug_assert_eq!(used, child.total_len(), "child length disagrees");
            items.push(item);
        }
        Ok((
            element.total_len(),
            Self {
                tag: element.tag().to_vec(),
                items,
            },
        ))
    }
}

impl<T: DecodeInner> Decode for Asn1Constructed<T> {
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new(options.clone()))
    }
}

impl<T: Encode> EncodeContent for Asn1Constructed<T> {
    /// The elements' TLVs back to back. Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.items.iter().map(|item| item.encoded_len(rules)).sum()
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let total = self.content_len(rules);
        let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
        let mut at = 0;
        for item in &self.items {
            at += item.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

/// The default header: definite length, or `80 ... 00 00` under CER and
/// indefinite BER, since the identifier is constructed.
impl<T: Encode> EncodeTagged for Asn1Constructed<T> {}

impl<T: Encode> Encode for Asn1Constructed<T> {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(&self.tag, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(&self.tag, rules, out)
    }
}
