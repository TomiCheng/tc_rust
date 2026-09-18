use crate::{Asn1Error, DecodingContext, DecodingOptions};

pub trait DecodeContent: Sized {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error>;

    fn decode_content_der(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error>;
}

pub trait DecodeConstructed: Sized {
    fn decode_constructed(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error>;
}

pub trait DecodeInner: Sized {
    fn decode_inner(buff: &[u8], context: &mut DecodingContext)
    -> Result<(usize, Self), Asn1Error>;

    fn decode_inner_der(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error>;
}

pub trait Decode: Sized {
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error>;
}
