//! RFC 5084 `CCMParameters`, the parameters of AES-CCM content encryption.
//!
//! ```text
//! CCMParameters ::= SEQUENCE {
//!     aes-nonce         OCTET STRING (SIZE(7..13)),
//!     aes-ICVlen        AES-CCM-ICVlen DEFAULT 12 }
//! AES-CCM-ICVlen ::= INTEGER (4 | 6 | 8 | 10 | 12 | 14 | 16)
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The default tag length, which is not written.
const DEFAULT_ICV_LEN: u8 = 12;

/// The nonce and tag length of AES-CCM.
///
/// The tag length is checked against the even values 4-16, as Bouncy Castle
/// does; anything else is `MalformedValue`. The nonce length is left to the
/// cipher. The default 12 is left out on output, and under DER an explicit 12
/// is `NotDer`.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::params::CcmParameters;
///
/// let params = CcmParameters::new(Asn1OctetString::new(&[0x24; 13]), 8)?;
/// let der = params.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(CcmParameters::decode_der(&der, &DecodingOptions::default())?.1, params);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CcmParameters {
    nonce: Asn1OctetString,
    icv_len: u8,
}

impl CcmParameters {
    /// The nonce and the tag length in octets, an even number from 4 to 16.
    /// Variable time: branches only on the encoding structure.
    pub fn new(nonce: Asn1OctetString, icv_len: u8) -> Result<Self, Asn1Error> {
        if !(4..=16).contains(&icv_len) || icv_len % 2 != 0 {
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

impl DecodeContent for CcmParameters {
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

impl DecodeInner for CcmParameters {
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

impl EncodeContent for CcmParameters {
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

impl Decode for CcmParameters {}

impl Tagged for CcmParameters {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CcmParameters {}

impl Encode for CcmParameters {
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

    use super::CcmParameters;

    #[test]
    fn even_tag_lengths_from_4_to_16_are_accepted_and_others_rejected() {
        for good in [4, 6, 8, 10, 12, 14, 16] {
            let value = CcmParameters::new(Asn1OctetString::new(&[1; 13]), good).unwrap();
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(wire.len(), if good == 12 { 17 } else { 20 });
            assert_eq!(
                CcmParameters::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
        for bad in [2, 5, 13, 18] {
            assert_eq!(
                CcmParameters::new(Asn1OctetString::new(&[1; 13]), bad),
                Err(Asn1Error::MalformedValue)
            );
        }
    }
}
