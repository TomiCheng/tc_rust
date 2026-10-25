//! X9.42 / RFC 2631 `OtherInfo`, the context hashed with ZZ to derive a KEK.
//!
//! ```text
//! OtherInfo ::= SEQUENCE {
//!     keyInfo     KeySpecificInfo,
//!     partyAInfo  [0] OCTET STRING OPTIONAL,  -- EXPLICIT
//!     suppPubInfo [2] OCTET STRING }          -- EXPLICIT
//! ```
//!
//! RFC 2631 puts the KEK length in bits, as four big-endian octets, in
//! `suppPubInfo`; that rule belongs to the derivation, so any octets are
//! carried here.

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

use crate::kdf::KeySpecificInfo;

/// The DER-encoded context of one X9.42 KEK derivation block.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x9::kdf::{KeySpecificInfo, OtherInfo};
///
/// let key_info = KeySpecificInfo::new("1.2.840.113549.1.9.16.3.6".parse()?, 1);
/// let info = OtherInfo::new(key_info, Asn1OctetString::new(&192u32.to_be_bytes()));
/// let der = info.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(OtherInfo::decode_der(&der, &DecodingOptions::default())?.1, info);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtherInfo {
    key_info: KeySpecificInfo,
    party_a_info: Option<Asn1OctetString>,
    supp_pub_info: Asn1OctetString,
}

impl OtherInfo {
    /// Stores the key information and the supplementary public information.
    /// Variable time: branches only on the encoding structure.
    pub fn new(key_info: KeySpecificInfo, supp_pub_info: Asn1OctetString) -> Self {
        Self {
            key_info,
            party_a_info: None,
            supp_pub_info,
        }
    }

    /// Adds party A's user keying material.
    /// Variable time: branches only on the encoding structure.
    pub fn with_party_a_info(mut self, party_a_info: Asn1OctetString) -> Self {
        self.party_a_info = Some(party_a_info);
        self
    }

    /// Returns the wrap algorithm and block counter.
    /// Variable time: branches only on the encoding structure.
    pub fn key_info(&self) -> &KeySpecificInfo {
        &self.key_info
    }

    /// Returns party A's user keying material, if supplied.
    /// Variable time: branches only on the encoding structure.
    pub fn party_a_info(&self) -> Option<&Asn1OctetString> {
        self.party_a_info.as_ref()
    }

    /// Returns the supplementary public information.
    /// Variable time: branches only on the encoding structure.
    pub fn supp_pub_info(&self) -> &Asn1OctetString {
        &self.supp_pub_info
    }
}

impl DecodeInner for OtherInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let key_info = fields.get()?;
        let party_a_info = fields.get_explicit_opt::<Asn1OctetString>([0xa0])?;
        let supp_pub_info = fields.get_explicit::<Asn1OctetString>([0xa2])?;
        fields.end()?;
        let mut value = Self::new(key_info, supp_pub_info);
        value.party_a_info = party_a_info;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for OtherInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.key_info.encoded_len(rules)
            + self
                .party_a_info
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + Explicit::new(&[0xa2], &self.supp_pub_info).encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.key_info.encode(rules, out)?;
        if let Some(v) = &self.party_a_info {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += Explicit::new(&[0xa2], &self.supp_pub_info).encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for OtherInfo {}

impl Tagged for OtherInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OtherInfo {}

impl Encode for OtherInfo {
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

    use tc_asn1::{Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::OtherInfo;
    use crate::kdf::KeySpecificInfo;

    fn key_info(arc: u8) -> KeySpecificInfo {
        let oid = alloc::format!("1.2.840.113549.1.9.16.3.{arc}");
        KeySpecificInfo::new(oid.parse().unwrap(), 1)
    }

    // RFC 2631 section 2.1.6, example 1: 3DES wrap, a 192-bit KEK, no partyAInfo.
    #[test]
    fn the_rfc_2631_first_example_encodes_byte_for_byte() {
        let value = OtherInfo::new(key_info(6), Asn1OctetString::new(&[0, 0, 0, 0xc0]));
        let wire = [
            0x30, 0x1d, 0x30, 0x13, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,
            0x10, 0x03, 0x06, 0x04, 0x04, 0x00, 0x00, 0x00, 0x01, 0xa2, 0x06, 0x04, 0x04, 0x00,
            0x00, 0x00, 0xc0,
        ];
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            OtherInfo::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    // The shape of RFC 2631 section 2.1.6, example 2: RC2 wrap, a 128-bit KEK and
    // 64 octets of partyAInfo.
    #[test]
    fn party_a_info_sits_between_the_key_info_and_supp_pub_info_under_every_rule() {
        let pattern = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let party_a = pattern.repeat(4);
        let value = OtherInfo::new(key_info(7), Asn1OctetString::new(&[0, 0, 0, 0x80]))
            .with_party_a_info(Asn1OctetString::new(&party_a));
        let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(der[..2], [0x30, 0x61]);
        assert_eq!(der[23..27], [0xa0, 0x42, 0x04, 0x40]);
        assert_eq!(
            der[der.len() - 8..],
            [0xa2, 0x06, 0x04, 0x04, 0, 0, 0, 0x80]
        );
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::DER,
            EncodingOptions::CER,
        ] {
            let wire = value.encode_to_vec(&rules).unwrap();
            assert_eq!(
                OtherInfo::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn a_missing_supp_pub_info_wrong_tags_and_reordered_fields_are_rejected() {
        let mut key = vec![0x30, 0x13, 0x06, 0x0b];
        key.extend_from_slice(&[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x06,
        ]);
        key.extend_from_slice(&[0x04, 0x04, 0, 0, 0, 1]);
        let supp = [0xa2, 0x06, 0x04, 0x04, 0, 0, 0, 0xc0];
        let party = [0xa0, 0x03, 0x04, 0x01, 0xaa];
        for (tail, error) in [
            (&[][..], Asn1Error::Truncated),
            (&party[..], Asn1Error::Truncated),
            // suppPubInfo under [1] instead of [2].
            (
                &[0xa1, 0x06, 0x04, 0x04, 0, 0, 0, 0xc0][..],
                Asn1Error::UnexpectedTag,
            ),
            // An INTEGER inside [2], rather than an OCTET STRING.
            (
                &[0xa2, 0x06, 0x02, 0x04, 0, 0, 0, 0xc0][..],
                Asn1Error::UnexpectedTag,
            ),
        ] {
            let mut wire = vec![0x30, (key.len() + tail.len()) as u8];
            wire.extend_from_slice(&key);
            wire.extend_from_slice(tail);
            assert_eq!(
                OtherInfo::decode_der(&wire, &DecodingOptions::default()),
                Err(error),
                "tail {tail:02x?}"
            );
        }
        let mut reordered = vec![0x30, (key.len() + supp.len() + party.len()) as u8];
        reordered.extend_from_slice(&key);
        reordered.extend_from_slice(&supp);
        reordered.extend_from_slice(&party);
        assert_eq!(
            OtherInfo::decode_der(&reordered, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }
}
