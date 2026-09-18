//! Shared by the constructed string forms and their CER limits (X.690 §9.2).

use alloc::vec::Vec;

use crate::{EncodingOptions, EncodingType, LengthForm};

/// CER writes a string primitive up to this many contents octets and
/// otherwise as 1000-octet segments.
pub(crate) const CER_SEGMENT_LEN: usize = 1000;

/// Segments are always primitive with definite length, whatever the outer rules.
pub(crate) const SEGMENT_RULES: EncodingOptions =
    EncodingOptions::new(EncodingType::Ber(LengthForm::Definite));

/// Whether CER forbids the primitive form for contents of this length.
pub(crate) fn too_long_for_cer(contents_len: usize, rules: &EncodingOptions) -> bool {
    rules.encoding_type() == EncodingType::Cer && contents_len > CER_SEGMENT_LEN
}

/// The identifier with the constructed bit cleared, for the primitive fallbacks.
pub(crate) fn primitive_tag(tag: &[u8]) -> Vec<u8> {
    let mut tag = tag.to_vec();
    if let Some(first) = tag.first_mut() {
        *first &= !0x20;
    }
    tag
}
