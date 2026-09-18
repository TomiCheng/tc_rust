use crate::{
    Asn1Error, Asn1OctetString, Asn1OctetStringConstructed, Asn1NumericString, Decode,
    DecodeConstructed, DecodeInner, DecodingContext, DecodingOptions, Encode, EncodeContent,
    EncodeTagged, EncodingOptions,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1NumericStringConstructed(Asn1OctetStringConstructed);

impl Asn1NumericStringConstructed {
    pub const TAG: &'static [u8] = super::tag::CONSTRUCTED_NUMERIC_STRING;

    pub fn segments(&self) -> &[Asn1OctetString] {
        self.0.segments()
    }

    pub fn split(value: &Asn1NumericString, segment_len: usize) -> Self {
        Self(Asn1OctetStringConstructed::split(
            &Asn1OctetString::new(value.as_str().as_bytes()),
            segment_len,
        ))
    }

    pub fn join(&self) -> Result<Asn1NumericString, Asn1Error> {
        Asn1NumericString::new(
            core::str::from_utf8(self.0.join().as_bytes()).map_err(|_| Asn1Error::MalformedValue)?,
        )
    }
}

impl DecodeConstructed for Asn1NumericStringConstructed {
    fn decode_constructed(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        Asn1OctetStringConstructed::decode_constructed(value, context).map(Self)
    }
}

impl DecodeInner for Asn1NumericStringConstructed {
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

impl Decode for Asn1NumericStringConstructed {
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new(options.clone()))
    }
}

impl EncodeContent for Asn1NumericStringConstructed {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.0.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.0.encode_content(rules, out)
    }
}

impl EncodeTagged for Asn1NumericStringConstructed {
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

impl Encode for Asn1NumericStringConstructed {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Asn1NumericString::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Asn1NumericString::TAG, rules, out)
    }
}
