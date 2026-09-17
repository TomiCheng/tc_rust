use alloc::vec::Vec;

use crate::Asn1Ref;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Any {
    raw: Vec<u8>,
    length_offset: usize,
    value_offset: usize,
    eoc_offset: usize,
}

impl Asn1Any {
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn as_ref(&self) -> Asn1Ref<'_> {
        Asn1Ref::from_validated_parts(
            &self.raw,
            self.length_offset,
            self.value_offset,
            self.eoc_offset,
        )
    }
}

impl From<&Asn1Ref<'_>> for Asn1Any {
    fn from(element: &Asn1Ref<'_>) -> Self {
        let eoc_offset = element.total_len() - element.eoc().len();
        Self {
            raw: element.raw().to_vec(),
            length_offset: element.tag().len(),
            value_offset: eoc_offset - element.value().len(),
            eoc_offset,
        }
    }
}

// impl DecodeInner for Asn1Any {
//     fn decode_inner(
//         buff: &[u8],
//         context: &mut DecodingContext,
//     ) -> Result<(usize, Self), Asn1Error> {
//         let element = Asn1Ref::parse(buff, context)?;
//         Ok((element.total_len(), Self::from(&element)))
//     }
//     fn decode_inner_der(
//         buff: &[u8],
//         context: &mut DecodingContext,
//     ) -> Result<(usize, Self), Asn1Error> {
//         let element = Asn1Ref::parse_der(buff, context)?;
//         crate::Asn1Object::decode_inner_der(element.raw(), context)?;
//         Ok((element.total_len(), Self::from(&element)))
//     }
// }
// impl Decode for Asn1Any {
//     fn decode(
//         buff: &[u8],
//         options: &crate::DecodingOptions,
//     ) -> Result<(usize, Self), crate::Asn1Error> {
//         <Self as DecodeInner<'a>>::decode_inner(
//             buff,
//             &mut DecodingContext::new(options),
//         )
//     }
// }
//
// impl crate::EncodeContent for Asn1Any {
//     fn content_len(&self, _: &EncodingOptions) -> usize {
//         self.as_ref().value().len()
//     }
//
//     fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
//         let len = crate::EncodeContent::content_len(self, rules);
//         let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
//         let value = self.as_ref().value();
//         out[..value.len()].copy_from_slice(value);
//         Ok(value.len())
//     }
// }
//
// impl crate::EncodeTagged for Asn1Any {}
//
// impl Encode for Asn1Any {
//     fn encoded_len(&self, _: &EncodingOptions) -> usize {
//         self.raw.len()
//     }
//
//     fn encode(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
//         let out = out
//             .get_mut(..self.raw.len())
//             .ok_or(Asn1Error::BufferTooSmall)?;
//         out.copy_from_slice(&self.raw);
//         Ok(self.raw.len())
//     }
// }
//
