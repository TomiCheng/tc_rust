//! RFC 5753 structures for elliptic-curve key agreement in CMS.
//!
//! An ECDH recipient derives its key-encryption key with the X9.63 KDF, whose
//! shared info is the DER [`EccCmsSharedInfo`]: the wrap algorithm, the
//! sender's optional user keying material and the KEK length.
//!
//! ```
//! use tc_asn1::{Asn1OctetString, Encode, EncodingOptions};
//! use tc_asn1_cms::ecc::EccCmsSharedInfo;
//! use tc_asn1_x509::alg::AlgorithmIdentifier;
//!
//! // A 256-bit KEK for AES-256 key wrap, with the UKM the sender chose.
//! let aes256_wrap = AlgorithmIdentifier::new("2.16.840.1.101.3.4.1.45".parse()?);
//! let ukm = [0x42; 64];
//! let shared_info = EccCmsSharedInfo::new(aes256_wrap, Asn1OctetString::new(&256u32.to_be_bytes()))
//!     .with_entity_u_info(Asn1OctetString::new(&ukm));
//!
//! // KEK = KDF2(Z, der) with the scheme's hash; the KEK length closes the encoding.
//! let der = shared_info.encode_to_vec(&EncodingOptions::DER)?;
//! assert!(der.ends_with(&[0xa2, 0x06, 0x04, 0x04, 0x00, 0x00, 0x01, 0x00]));
//! # Ok::<(), tc_asn1::Asn1Error>(())
//! ```

mod ecc_cms_shared_info;
mod mqv_user_keying_material;

pub use ecc_cms_shared_info::EccCmsSharedInfo;
pub use mqv_user_keying_material::MqvUserKeyingMaterial;
