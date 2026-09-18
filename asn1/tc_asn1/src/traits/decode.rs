use crate::{Asn1Error, DecodingContext, DecodingOptions};

/// Reads the contents octets of a primitive encoding. Types with DER
/// contents rules (BOOLEAN, BIT STRING, REAL, the time types) check them when
/// `context.is_der()`.
pub trait DecodeContent: Sized {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error>;
}

/// Reads the contents octets of a constructed encoding.
pub trait DecodeConstructed: Sized {
    fn decode_constructed(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error>;
}

/// Reads one complete TLV from the start of `buff` with the caller's context,
/// returning the octets used. The DER rules follow the context's flag.
pub trait DecodeInner: Sized {
    fn decode_inner(buff: &[u8], context: &mut DecodingContext)
    -> Result<(usize, Self), Asn1Error>;
}

/// The standalone entry points: a fresh context per call, BER-lenient or DER.
pub trait Decode: DecodeInner {
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new(options.clone()))
    }

    fn decode_der(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new_der(options.clone()))
    }
}
