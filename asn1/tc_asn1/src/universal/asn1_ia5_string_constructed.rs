use crate::{
    Asn1Error, Asn1Ia5String, Asn1OctetString, Asn1OctetStringConstructed, Decode,
    DecodeConstructed, DecodeInner, DecodingContext, DecodingOptions, Encode, EncodeContent,
    EncodeTagged, EncodingOptions,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Ia5StringConstructed(Asn1OctetStringConstructed);

impl Asn1Ia5StringConstructed {
    pub const TAG: &'static [u8] = super::tag::CONSTRUCTED_IA5_STRING;

    pub fn segments(&self) -> &[Asn1OctetString] {
        self.0.segments()
    }

    /// Splits a value into segments of at most `segment_len` octets (at least 1).
    /// Variable time: branches only on the value's length.
    pub fn split(value: &Asn1Ia5String, segment_len: usize) -> Self {
        Self(Asn1OctetStringConstructed::split(
            &Asn1OctetString::new(value.as_str().as_bytes()),
            segment_len,
        ))
    }

    /// Concatenates the segments and validates the text as IA5.
    /// Variable time: branches only on the contents.
    pub fn join(&self) -> Result<Asn1Ia5String, Asn1Error> {
        Asn1Ia5String::new(
            core::str::from_utf8(self.0.join().as_bytes()).map_err(|_| Asn1Error::MalformedValue)?,
        )
    }
}

impl DecodeConstructed for Asn1Ia5StringConstructed {
    fn decode_constructed(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        Asn1OctetStringConstructed::decode_constructed(value, context).map(Self)
    }
}

impl DecodeInner for Asn1Ia5StringConstructed {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, inner) = Asn1OctetStringConstructed::decode_tagged(Self::TAG, buff, context)?;
        Ok((used, Self(inner)))
    }

    fn decode_inner_der(_: &[u8], _: &mut DecodingContext) -> Result<(usize, Self), Asn1Error> {
        // The constructed form is never DER (X.690 §10.2).
        Err(Asn1Error::NotDer)
    }
}

impl Decode for Asn1Ia5StringConstructed {
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new(options.clone()))
    }
}

impl EncodeContent for Asn1Ia5StringConstructed {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.0.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.0.encode_content(rules, out)
    }
}

impl EncodeTagged for Asn1Ia5StringConstructed {
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        self.0.encoded_len_tagged(tag, rules)
    }

    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        self.0.encode_tagged(tag, rules, out)
    }
}

impl Encode for Asn1Ia5StringConstructed {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Asn1Ia5String::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Asn1Ia5String::TAG, rules, out)
    }
}
