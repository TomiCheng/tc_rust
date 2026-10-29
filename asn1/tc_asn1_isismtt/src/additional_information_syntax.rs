//! Common PKI `AdditionalInformationSyntax`, the value of the additionalInformation
//! attribute.
//!
//! ```text
//! AdditionalInformationSyntax ::= DirectoryString (SIZE(1..2048))
//! ```

use tc_asn1_x500::DirectoryString;

/// Free text about the holder.
pub type AdditionalInformationSyntax = DirectoryString;
