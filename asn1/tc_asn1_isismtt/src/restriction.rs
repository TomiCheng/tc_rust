//! Common PKI `RestrictionSyntax`, the value of the restriction attribute.
//!
//! ```text
//! RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
//! ```

use tc_asn1_x500::DirectoryString;

/// Free text restricting how the certificate may be used.
pub type Restriction = DirectoryString;
