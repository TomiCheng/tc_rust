//! X9.42 / RFC 2631 key-specific information for the Diffie-Hellman KEK derivation.
//!
//! ```text
//! KeySpecificInfo ::= SEQUENCE {
//!     algorithm OBJECT IDENTIFIER,
//!     counter   OCTET STRING SIZE (4..4) }
//! ```
//!
//! `algorithm` names the key-wrap algorithm the derived key is for, such as
//! `id-alg-CMS3DESwrap`; `counter` numbers the derivation block, starting at 1.

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Oid, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The wrap algorithm and the 32-bit block counter of one KEK derivation step.
///
/// The counter is held as a `u32`, so the `SIZE (4..4)` constraint holds by
/// construction; decoding rejects any other length with `MalformedValue`.
///
/// ```
/// use tc_asn1::{Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::KeySpecificInfo;
///
/// let cms3deswrap: Asn1Oid = "1.2.840.113549.1.9.16.3.6".parse()?;
/// let info = KeySpecificInfo::new(cms3deswrap, 1);
/// let der = info.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(KeySpecificInfo::decode_der(&der, &DecodingOptions::default())?.1, info);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct KeySpecificInfo {
    algorithm: Asn1Oid,
    counter: u32,
}

impl KeySpecificInfo {
    /// Stores the wrap algorithm and the block counter.
    /// Variable time: branches only on the encoding structure.
    pub fn new(algorithm: Asn1Oid, counter: u32) -> Self {
        Self { algorithm, counter }
    }

    /// Returns the key-wrap algorithm identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn algorithm(&self) -> &Asn1Oid {
        &self.algorithm
    }

    /// Returns the block counter.
    /// Variable time: branches only on the encoding structure.
    pub fn counter(&self) -> u32 {
        self.counter
    }
}

impl DecodeInner for KeySpecificInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let algorithm = fields.get()?;
        let counter: Asn1OctetString = fields.get()?;
        fields.end()?;
        let counter =
            <[u8; 4]>::try_from(counter.as_bytes()).map_err(|_| Asn1Error::MalformedValue)?;
        Ok((
            element.total_len(),
            Self::new(algorithm, u32::from_be_bytes(counter)),
        ))
    }
}

impl EncodeContent for KeySpecificInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.algorithm.encoded_len(rules) + 6
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.algorithm.encode(rules, out)?;
        let counter = out.get_mut(at..at + 6).ok_or(Asn1Error::BufferTooSmall)?;
        counter[..2].copy_from_slice(&[0x04, 0x04]);
        counter[2..].copy_from_slice(&self.counter.to_be_bytes());
        Ok(at + 6)
    }
}

impl Decode for KeySpecificInfo {}

impl Tagged for KeySpecificInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for KeySpecificInfo {}

impl Encode for KeySpecificInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::KeySpecificInfo;

    const CMS3DESWRAP: &[u8] = &[
        0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x06,
    ];

    #[test]
    fn the_rfc_2631_example_key_info_encodes_with_a_big_endian_four_octet_counter() {
        let value = KeySpecificInfo::new("1.2.840.113549.1.9.16.3.6".parse().unwrap(), 1);
        let mut wire = vec![0x30, 0x13];
        wire.extend_from_slice(CMS3DESWRAP);
        wire.extend_from_slice(&[0x04, 0x04, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::DER,
            EncodingOptions::CER,
        ] {
            let wire = value.encode_to_vec(&rules).unwrap();
            assert_eq!(
                KeySpecificInfo::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
        let last = KeySpecificInfo::new(value.algorithm().clone(), u32::MAX);
        let wire = last.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire[wire.len() - 4..], [0xff; 4]);
    }

    #[test]
    fn counters_that_are_not_exactly_four_octets_are_rejected() {
        for counter in [&[][..], &[1][..], &[0, 0, 1][..], &[0, 0, 0, 0, 1][..]] {
            let mut content = CMS3DESWRAP.to_vec();
            content.extend_from_slice(&[0x04, counter.len() as u8]);
            content.extend_from_slice(counter);
            let mut wire = vec![0x30, content.len() as u8];
            wire.extend_from_slice(&content);
            assert_eq!(
                KeySpecificInfo::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn a_missing_counter_or_swapped_fields_are_rejected() {
        let mut missing = vec![0x30, CMS3DESWRAP.len() as u8];
        missing.extend_from_slice(CMS3DESWRAP);
        assert_eq!(
            KeySpecificInfo::decode_der(&missing, &DecodingOptions::default()),
            Err(Asn1Error::Truncated)
        );
        let mut swapped = vec![0x30, 0x13, 0x04, 0x04, 0, 0, 0, 1];
        swapped.extend_from_slice(CMS3DESWRAP);
        assert_eq!(
            KeySpecificInfo::decode_der(&swapped, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
