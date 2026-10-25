//! RFC 5753 §7.2 `ECC-CMS-SharedInfo`.
//!
//! ```text
//! ECC-CMS-SharedInfo ::= SEQUENCE {
//!     keyInfo         AlgorithmIdentifier,
//!     entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
//!     suppPubInfo [2] EXPLICIT OCTET STRING }
//! ```
//!
//! RFC 5753 puts the KEK length in bits, as four big-endian octets, in
//! `suppPubInfo`; that rule belongs to the derivation, so any octets are
//! carried here.

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The shared info of the X9.63 KDF in CMS elliptic-curve key agreement, BC's
/// `ECC_CMS_SharedInfo`.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::ecc::EccCmsSharedInfo;
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// let aes128_wrap = AlgorithmIdentifier::new("2.16.840.1.101.3.4.1.5".parse()?);
/// let info = EccCmsSharedInfo::new(aes128_wrap, Asn1OctetString::new(&128u32.to_be_bytes()));
/// let der = info.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(EccCmsSharedInfo::decode_der(&der, &DecodingOptions::default())?.1, info);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EccCmsSharedInfo {
    key_info: AlgorithmIdentifier,
    entity_u_info: Option<Asn1OctetString>,
    supp_pub_info: Asn1OctetString,
}

impl EccCmsSharedInfo {
    /// Stores the wrap algorithm and the supplementary public information.
    /// Variable time: branches only on the encoding structure.
    pub fn new(key_info: AlgorithmIdentifier, supp_pub_info: Asn1OctetString) -> Self {
        Self {
            key_info,
            entity_u_info: None,
            supp_pub_info,
        }
    }

    /// Adds the sender's user keying material.
    /// Variable time: branches only on the encoding structure.
    pub fn with_entity_u_info(mut self, entity_u_info: Asn1OctetString) -> Self {
        self.entity_u_info = Some(entity_u_info);
        self
    }

    /// Returns the key-wrap algorithm the KEK is for.
    /// Variable time: branches only on the encoding structure.
    pub fn key_info(&self) -> &AlgorithmIdentifier {
        &self.key_info
    }

    /// Returns the sender's user keying material, if supplied.
    /// Variable time: branches only on the encoding structure.
    pub fn entity_u_info(&self) -> Option<&Asn1OctetString> {
        self.entity_u_info.as_ref()
    }

    /// Returns the supplementary public information.
    /// Variable time: branches only on the encoding structure.
    pub fn supp_pub_info(&self) -> &Asn1OctetString {
        &self.supp_pub_info
    }
}

impl DecodeInner for EccCmsSharedInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let key_info = fields.get()?;
        let entity_u_info = fields.get_explicit_opt::<Asn1OctetString>([0xa0])?;
        let supp_pub_info = fields.get_explicit::<Asn1OctetString>([0xa2])?;
        fields.end()?;
        let mut value = Self::new(key_info, supp_pub_info);
        value.entity_u_info = entity_u_info;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for EccCmsSharedInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.key_info.encoded_len(rules)
            + self
                .entity_u_info
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + Explicit::new(&[0xa2], &self.supp_pub_info).encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.key_info.encode(rules, out)?;
        if let Some(v) = &self.entity_u_info {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += Explicit::new(&[0xa2], &self.supp_pub_info).encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for EccCmsSharedInfo {}

impl Tagged for EccCmsSharedInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EccCmsSharedInfo {}

impl Encode for EccCmsSharedInfo {
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
    use tc_asn1_x509::alg::AlgorithmIdentifier;

    use super::EccCmsSharedInfo;

    const AES128_WRAP: &[u8] = &[
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05,
    ];
    const SUPP_PUB_INFO_128: &[u8] = &[0xa2, 0x06, 0x04, 0x04, 0x00, 0x00, 0x00, 0x80];

    fn aes128_wrap() -> AlgorithmIdentifier {
        AlgorithmIdentifier::new("2.16.840.1.101.3.4.1.5".parse().unwrap())
    }

    #[test]
    fn the_wrap_algorithm_and_kek_length_encode_without_entity_u_info() {
        let value = EccCmsSharedInfo::new(aes128_wrap(), Asn1OctetString::new(&[0, 0, 0, 0x80]));
        let mut wire = vec![0x30, 0x15];
        wire.extend_from_slice(AES128_WRAP);
        wire.extend_from_slice(SUPP_PUB_INFO_128);
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            EccCmsSharedInfo::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn entity_u_info_sits_between_the_key_info_and_supp_pub_info_under_every_rule() {
        let value = EccCmsSharedInfo::new(
            AlgorithmIdentifier::with_null("2.16.840.1.101.3.4.1.5".parse().unwrap()),
            Asn1OctetString::new(&[0, 0, 0, 0x80]),
        )
        .with_entity_u_info(Asn1OctetString::new(&[0x42; 64]));
        let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(der[2..4], [0x30, 0x0d]);
        assert_eq!(der[17..21], [0xa0, 0x42, 0x04, 0x40]);
        assert_eq!(der[der.len() - 8..], *SUPP_PUB_INFO_128);
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::DER,
            EncodingOptions::CER,
        ] {
            let wire = value.encode_to_vec(&rules).unwrap();
            let decoded = EccCmsSharedInfo::decode(&wire, &DecodingOptions::default())
                .unwrap()
                .1;
            assert_eq!(decoded, value);
            assert_eq!(decoded.entity_u_info().unwrap().as_bytes(), &[0x42; 64]);
        }
    }

    #[test]
    fn a_missing_supp_pub_info_wrong_tags_and_reordered_fields_are_rejected() {
        let entity = [0xa0, 0x03, 0x04, 0x01, 0xaa];
        for (tail, error) in [
            (&[][..], Asn1Error::Truncated),
            (&entity[..], Asn1Error::Truncated),
            // suppPubInfo under [1] instead of [2].
            (
                &[0xa1, 0x06, 0x04, 0x04, 0, 0, 0, 0x80][..],
                Asn1Error::UnexpectedTag,
            ),
            // An INTEGER inside [2], rather than an OCTET STRING.
            (
                &[0xa2, 0x06, 0x02, 0x04, 0, 0, 0, 0x80][..],
                Asn1Error::UnexpectedTag,
            ),
        ] {
            let mut wire = vec![0x30, (AES128_WRAP.len() + tail.len()) as u8];
            wire.extend_from_slice(AES128_WRAP);
            wire.extend_from_slice(tail);
            assert_eq!(
                EccCmsSharedInfo::decode_der(&wire, &DecodingOptions::default()),
                Err(error),
                "tail {tail:02x?}"
            );
        }
        let mut reordered = vec![
            0x30,
            (AES128_WRAP.len() + SUPP_PUB_INFO_128.len() + entity.len()) as u8,
        ];
        reordered.extend_from_slice(AES128_WRAP);
        reordered.extend_from_slice(SUPP_PUB_INFO_128);
        reordered.extend_from_slice(&entity);
        assert_eq!(
            EccCmsSharedInfo::decode_der(&reordered, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }
}
