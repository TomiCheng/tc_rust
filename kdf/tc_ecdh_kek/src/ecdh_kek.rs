use core::convert::Infallible;

use tc_asn1::{Asn1OctetString, Encode, EncodingOptions};
use tc_asn1_cms::ecc::EccCmsSharedInfo;
use tc_digest::Digest;
use tc_kdf::kdf::{Kdf2, KdfParamsRef};
use tc_kdf::{Kdf, KdfError, KdfInit};

use crate::EcdhKekParams;

/// The RFC 5753 ECDH KEK derivation, BC's `ECDHKekGenerator`: the X9.63 KDF
/// (KDF2) over Z with the DER `ECC-CMS-SharedInfo` as its shared info.
///
/// Every call to `generate_bytes` starts over from the first block, as KDF2
/// does. Z is copied into the KDF at `init` and wiped when replaced and on drop.
pub struct EcdhKek<D> {
    kdf: Kdf2<D>,
}

impl<D> EcdhKek<D> {
    /// A function over `digest`, not yet initialized. Constant time.
    pub const fn new(digest: D) -> Self {
        Self {
            kdf: Kdf2::new(digest),
        }
    }
}

impl<D, P> KdfInit<P> for EcdhKek<D>
where
    P: EcdhKekParams + ?Sized,
{
    type Error = Infallible;

    /// Encodes the shared info and initializes KDF2 with Z and it. Any parameters
    /// are accepted, as in BC. Constant time with respect to Z.
    fn init(&mut self, params: &P) -> Result<(), Infallible> {
        let mut shared_info = EccCmsSharedInfo::new(
            params.key_info().clone(),
            Asn1OctetString::new(&params.key_size().to_be_bytes()),
        );
        if !params.extra_info().is_empty() {
            shared_info = shared_info.with_entity_u_info(Asn1OctetString::new(params.extra_info()));
        }
        let shared_info = shared_info
            .encode_to_vec(&EncodingOptions::DER)
            .expect("ECC-CMS-SharedInfo encodes into a buffer of its own length");
        self.kdf
            .init(&KdfParamsRef::with_iv(params.z(), &shared_info))
    }
}

impl<D: Digest> Kdf for EcdhKek<D> {
    type Error = KdfError;

    /// Fills `output` from the first block on, as KDF2 does. Fails before `init`,
    /// or when `output` is longer than `(2^32 - 1) * digest size` bytes. Constant
    /// time with respect to Z when the digest is; the output length is public.
    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, KdfError> {
        self.kdf.generate_bytes(output)
    }
}
