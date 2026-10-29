//! RFC 7292 §4.1 `AuthenticatedSafe`, the contents of a PKCS #12 file: a sequence
//! of plain, encrypted or enveloped `ContentInfo`s, each holding `SafeContents`.
//!
//! ```text
//! AuthenticatedSafe ::= SEQUENCE OF ContentInfo
//!     -- Data if unencrypted
//!     -- EncryptedData if password-encrypted
//!     -- EnvelopedData if public key-encrypted
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_cms::content::ContentInfo;

/// The `ContentInfo`s of a PKCS #12 file, in order.
///
/// ```
/// use tc_asn1::{Asn1Any, Decode, DecodingOptions, Encode, EncodingOptions, tag};
/// use tc_asn1_cms::content::{ContentInfo, ContentType};
/// use tc_asn1_pkcs::AuthenticatedSafe;
///
/// let keys = ContentInfo::new(ContentType::DATA.oid())
///     .with_content(Asn1Any::primitive(tag::OCTET_STRING, &[0x30, 0x00]));
/// let safe = AuthenticatedSafe::new(vec![keys]);
///
/// let der = safe.encode_to_vec(&EncodingOptions::DER)?;
/// let back = AuthenticatedSafe::decode_der(&der, &DecodingOptions::default())?.1;
/// assert_eq!(back.content_infos().len(), 1);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AuthenticatedSafe {
    content_infos: Asn1SequenceOf<ContentInfo>,
}

impl AuthenticatedSafe {
    /// The `ContentInfo`s, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(content_infos: Vec<ContentInfo>) -> Self {
        Self {
            content_infos: Asn1SequenceOf::new(content_infos),
        }
    }

    /// Returns the `ContentInfo`s in order.
    /// Variable time: branches only on the encoding structure.
    pub fn content_infos(&self) -> &[ContentInfo] {
        self.content_infos.elements()
    }
}

impl DecodeContent for AuthenticatedSafe {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        Ok(Self {
            content_infos: Asn1SequenceOf::decode_content(value, context)?,
        })
    }
}

impl DecodeInner for AuthenticatedSafe {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, content_infos) = Asn1SequenceOf::decode_inner(buff, context)?;
        Ok((len, Self { content_infos }))
    }
}

impl EncodeContent for AuthenticatedSafe {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.content_infos.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.content_infos.encode_content(rules, out)
    }
}

impl Decode for AuthenticatedSafe {}

impl Tagged for AuthenticatedSafe {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for AuthenticatedSafe {}

impl Encode for AuthenticatedSafe {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
