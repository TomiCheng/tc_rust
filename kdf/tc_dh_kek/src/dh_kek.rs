use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;

use tc_asn1::{Asn1OctetString, Asn1Oid, Encode, EncodingOptions};
use tc_asn1_x9::kdf::{KeySpecificInfo, OtherInfo};
use tc_digest::Digest;
use tc_kdf::{Kdf, KdfError, KdfInit};
use tc_zeroize::Zeroize;

use crate::DhKekParams;

/// The RFC 2631 Diffie-Hellman KEK derivation, BC's `DHKekGenerator`: block `i` is
/// `Hash(ZZ || DER(OtherInfo))`, with `i` as the `KeySpecificInfo` counter, starting at 1.
///
/// Every call to `generate_bytes` starts over from the first block, as in BC. ZZ and the
/// extra info copied at `init` are wiped when replaced and on drop.
pub struct DhKek<D> {
    digest: D,
    parameters: Option<Parameters>,
}

/// 從 init 的參數複製下來的值；ZZ 與 extraInfo 在 drop 時清除。
struct Parameters {
    algorithm: Asn1Oid,
    key_size: u32,
    z: Vec<u8>,
    extra_info: Vec<u8>,
}

impl Drop for Parameters {
    fn drop(&mut self) {
        self.z.zeroize();
        self.extra_info.zeroize();
    }
}

impl<D> DhKek<D> {
    /// A function over `digest`, not yet initialized. Constant time.
    pub const fn new(digest: D) -> Self {
        Self {
            digest,
            parameters: None,
        }
    }
}

impl<D, P> KdfInit<P> for DhKek<D>
where
    P: DhKekParams + ?Sized,
{
    type Error = Infallible;

    /// Copies the parameters. Any parameters are accepted, as in BC. Constant time with respect
    /// to ZZ.
    fn init(&mut self, params: &P) -> Result<(), Infallible> {
        self.parameters = Some(Parameters {
            algorithm: params.algorithm().clone(),
            key_size: params.key_size(),
            z: params.z().to_vec(),
            extra_info: params.extra_info().to_vec(),
        });
        Ok(())
    }
}

impl<D: Digest> Kdf for DhKek<D> {
    type Error = KdfError;

    /// Fills `output` from the first block on. Fails before `init`, or when `output` is longer
    /// than `(2^32 - 1) * digest size` bytes. Constant time with respect to ZZ when the digest
    /// is; the output length and the public parameters decide the work.
    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, KdfError> {
        let parameters = self.parameters.as_ref().ok_or(KdfError::NotInitialised)?;
        let digest_size = self.digest.digest_size();
        if output.len() as u64 > u64::from(u32::MAX) * digest_size as u64 {
            return Err(KdfError::OutputTooLong);
        }
        self.digest.reset();

        let supp_pub_info = Asn1OctetString::new(&parameters.key_size.to_be_bytes());
        let mut last = Vec::new();
        for (index, block) in output.chunks_mut(digest_size).enumerate() {
            // 上面的長度上限保證 index + 1 放得進 u32。
            let counter = index as u32 + 1;
            let key_info = KeySpecificInfo::new(parameters.algorithm.clone(), counter);
            let mut other_info = OtherInfo::new(key_info, supp_pub_info.clone());
            if !parameters.extra_info.is_empty() {
                other_info =
                    other_info.with_party_a_info(Asn1OctetString::new(&parameters.extra_info));
            }
            let other_info = other_info
                .encode_to_vec(&EncodingOptions::DER)
                .expect("OtherInfo encodes into a buffer of its own length");

            self.digest.update(&parameters.z);
            self.digest.update(&other_info);
            if block.len() == digest_size {
                self.digest.do_final(block);
            } else {
                last = vec![0; digest_size];
                self.digest.do_final(&mut last);
                block.copy_from_slice(&last[..block.len()]);
            }
        }
        last.zeroize();
        Ok(output.len())
    }
}
