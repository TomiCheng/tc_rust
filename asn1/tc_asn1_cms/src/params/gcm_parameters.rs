//! RFC 5084 `GCMParameters`, the parameters of AES-GCM content encryption.
//!
//! ```text
//! GCMParameters ::= SEQUENCE {
//!     aes-nonce        OCTET STRING, -- recommended size is 12 octets
//!     aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
//! AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16)
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The default and most common tag length, which is not written.
const DEFAULT_ICV_LEN: u8 = 12;

/// The nonce and tag length of AES-GCM.
///
/// The tag length is checked against 12-16, as Bouncy Castle does; anything else
/// is `MalformedValue`. The default 12 is left out on output, and under DER an
/// explicit 12 is `NotDer`.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::params::GcmParameters;
///
/// let params = GcmParameters::new(Asn1OctetString::new(&[0x24; 12]), 16)?;
/// let der = params.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(GcmParameters::decode_der(&der, &DecodingOptions::default())?.1, params);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GcmParameters {
    nonce: Asn1OctetString,
    icv_len: u8,
}

impl GcmParameters {
    /// The nonce and the tag length in octets, 12-16.
    /// Variable time: branches only on the encoding structure.
    pub fn new(nonce: Asn1OctetString, icv_len: u8) -> Result<Self, Asn1Error> {
        if !(12..=16).contains(&icv_len) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { nonce, icv_len })
    }

    /// Returns the nonce.
    /// Variable time: branches only on the encoding structure.
    pub fn nonce(&self) -> &Asn1OctetString {
        &self.nonce
    }

    /// Returns the tag length in octets.
    /// Variable time: branches only on the encoding structure.
    pub fn icv_len(&self) -> u8 {
        self.icv_len
    }
}

impl DecodeContent for GcmParameters {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let nonce = fields.get()?;
        let icv_len = fields.get_default(Asn1Integer::from(DEFAULT_ICV_LEN))?;
        fields.end()?;
        let icv_len = u8::try_from(&icv_len).map_err(|_| Asn1Error::MalformedValue)?;
        Self::new(nonce, icv_len)
    }
}

impl DecodeInner for GcmParameters {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for GcmParameters {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.nonce.encoded_len(rules)
            + if self.icv_len == DEFAULT_ICV_LEN {
                0
            } else {
                Asn1Integer::from(self.icv_len).encoded_len(rules)
            }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.nonce.encode(rules, out)?;
        if self.icv_len != DEFAULT_ICV_LEN {
            at += Asn1Integer::from(self.icv_len).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for GcmParameters {}

impl Tagged for GcmParameters {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for GcmParameters {}

impl Encode for GcmParameters {
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
    use tc_asn1::{Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::GcmParameters;

    #[test]
    fn the_default_tag_length_is_left_out_and_others_are_written() {
        let default = GcmParameters::new(Asn1OctetString::new(&[1; 12]), 12).unwrap();
        let wire = default.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire[..4], [0x30, 0x0e, 0x04, 0x0c]);
        assert_eq!(wire.len(), 16);
        let sixteen = GcmParameters::new(Asn1OctetString::new(&[1; 12]), 16).unwrap();
        let wire16 = sixteen.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire16[wire16.len() - 3..], [0x02, 0x01, 0x10]);
        for (value, wire) in [(default, wire), (sixteen, wire16)] {
            assert_eq!(
                GcmParameters::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn tag_lengths_outside_12_to_16_and_an_explicit_default_under_der_are_rejected() {
        for bad in [11, 17] {
            assert_eq!(
                GcmParameters::new(Asn1OctetString::new(&[1; 12]), bad),
                Err(Asn1Error::MalformedValue)
            );
        }
        let mut explicit_default = alloc::vec![0x30, 0x11, 0x04, 0x0c];
        explicit_default.extend_from_slice(&[1; 12]);
        explicit_default.extend_from_slice(&[0x02, 0x01, 0x0c]);
        assert_eq!(
            GcmParameters::decode_der(&explicit_default, &DecodingOptions::default()),
            Err(Asn1Error::NotDer)
        );
        assert_eq!(
            GcmParameters::decode(&explicit_default, &DecodingOptions::default())
                .unwrap()
                .1
                .icv_len(),
            12
        );
        explicit_default[18] = 0x08;
        assert_eq!(
            GcmParameters::decode(&explicit_default, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }
}
