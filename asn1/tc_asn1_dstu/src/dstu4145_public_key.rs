//! The DSTU 4145 public key, a compressed point in an OCTET STRING inside the
//! subject public key BIT STRING.

use tc_asn1::Asn1OctetString;

/// The compressed public point; encoding the point is the curve's job.
pub type Dstu4145PublicKey = Asn1OctetString;
