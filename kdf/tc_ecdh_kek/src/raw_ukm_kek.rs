use core::convert::Infallible;

use tc_digest::Digest;
use tc_kdf::kdf::{Kdf2, KdfParamsRef};
use tc_kdf::{Kdf, KdfError, KdfInit};

use crate::EcdhKekParams;

/// The non-conformant ECDH KEK derivation that uses the user keying material
/// itself as KDF2's shared info, BC's internal `RawUkmKekGenerator`.
///
/// RFC 5753 §7.2 requires the DER `ECC-CMS-SharedInfo`, which [`EcdhKek`]
/// derives. This exists only to read messages from senders that did this
/// instead, among them bc-java 1.53 to 1.86 for 1-Pass ECMQV. The key-wrap
/// algorithm and KEK length are not part of the derivation.
///
/// [`EcdhKek`]: crate::EcdhKek
pub struct RawUkmKek<D> {
    kdf: Kdf2<D>,
}

impl<D> RawUkmKek<D> {
    /// A function over `digest`, not yet initialized. Constant time.
    pub const fn new(digest: D) -> Self {
        Self {
            kdf: Kdf2::new(digest),
        }
    }
}

impl<D, P> KdfInit<P> for RawUkmKek<D>
where
    P: EcdhKekParams + ?Sized,
{
    type Error = Infallible;

    /// Initializes KDF2 with Z and the user keying material. Any parameters are
    /// accepted, as in BC. Constant time with respect to Z.
    fn init(&mut self, params: &P) -> Result<(), Infallible> {
        self.kdf
            .init(&KdfParamsRef::with_iv(params.z(), params.extra_info()))
    }
}

impl<D: Digest> Kdf for RawUkmKek<D> {
    type Error = KdfError;

    /// Fills `output` from the first block on, as KDF2 does. Fails before `init`,
    /// or when `output` is longer than `(2^32 - 1) * digest size` bytes. Constant
    /// time with respect to Z when the digest is; the output length is public.
    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, KdfError> {
        self.kdf.generate_bytes(output)
    }
}
