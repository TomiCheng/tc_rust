//! RFC 2634 §2.7 `ContentIdentifier`, the value of the content-identifier
//! attribute.
//!
//! ```text
//! ContentIdentifier ::= OCTET STRING
//! ```

use tc_asn1::Asn1OctetString;

/// An identifier for the content, unique to its originator.
pub type ContentIdentifier = Asn1OctetString;
