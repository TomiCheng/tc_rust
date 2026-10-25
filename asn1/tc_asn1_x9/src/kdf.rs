//! X9.42 key-derivation context: the `OtherInfo` hashed with the shared
//! secret to derive a Diffie-Hellman KEK, and its `KeySpecificInfo`.
//!
//! RFC 2631 derives a KEK one hash block at a time; each block hashes the
//! shared secret ZZ followed by an `OtherInfo` carrying that block's counter:
//!
//! ```
//! use tc_asn1::{Asn1OctetString, Asn1Oid, Encode, EncodingOptions};
//! use tc_asn1_x9::kdf::{KeySpecificInfo, OtherInfo};
//!
//! // A 192-bit 3DES wrap key takes two SHA-1 blocks.
//! let zz = [0x5a; 20];
//! let cms3deswrap: Asn1Oid = "1.2.840.113549.1.9.16.3.6".parse()?;
//! let kek_bits = 192u32;
//!
//! let mut hash_inputs = Vec::new();
//! for counter in 1..=2 {
//!     let info = OtherInfo::new(
//!         KeySpecificInfo::new(cms3deswrap.clone(), counter),
//!         Asn1OctetString::new(&kek_bits.to_be_bytes()),
//!     );
//!     let der = info.encode_to_vec(&EncodingOptions::DER)?;
//!     hash_inputs.push([&zz[..], &der].concat());
//! }
//!
//! // SHA-1 over each input gives one block; the KEK is the first 24 octets.
//! assert_eq!(hash_inputs.len(), 2);
//! # Ok::<(), tc_asn1::Asn1Error>(())
//! ```

mod key_specific_info;
mod other_info;

pub use key_specific_info::KeySpecificInfo;
pub use other_info::OtherInfo;
