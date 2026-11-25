use crate::{AgreementWithKdfError, EcdhKekParamsRef, UkmParams};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::convert::Infallible;
use tc_agreement::{Agreement, AgreementInit};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_kdf::{Kdf, KdfInit};
use tc_zeroize::Zeroizing;

/// Bouncy Castle's `ECDHWithKdfBasicAgreement`, `ECDHCWithKdfBasicAgreement`
/// and `ECMqvWithKdfBasicAgreement`, which differ only in the agreement
/// underneath, as one generic: agreement `A` makes Z, and KDF `K`, an
/// [`EcdhKek`](crate::EcdhKek) or [`RawUkmKek`](crate::RawUkmKek), derives a
/// key of `key_size / 8` bytes from Z, `key_info`, `key_size` and the UKM.
///
/// Bouncy Castle looks the key size up from `key_info` with
/// `GeneratorUtilities.GetDefaultKeySize`; here the caller gives it. Bouncy
/// Castle returns the key as an integer, which drops leading zeros; here it
/// keeps its fixed length.
pub struct AgreementWithKdf<A, K> {
    agreement: A,
    kdf: RefCell<K>,
    key_info: AlgorithmIdentifier,
    key_size: u32,
    ukm: Vec<u8>,
    initialized: bool,
}

impl<A, K> AgreementWithKdf<A, K> {
    /// An agreement that runs `agreement` and derives with `kdf` a key of
    /// `key_size` bits for `key_info`, not initialized yet. Constant time.
    pub fn new(agreement: A, kdf: K, key_info: AlgorithmIdentifier, key_size: u32) -> Self {
        Self {
            agreement,
            kdf: RefCell::new(kdf),
            key_info,
            key_size,
            ukm: Vec::new(),
            initialized: false,
        }
    }
}

impl<A: AgreementInit<P>, K, P> AgreementInit<UkmParams<P>> for AgreementWithKdf<A, K> {
    type Error = A::Error;

    /// Bouncy Castle's `Init`: keeps the UKM and initializes the agreement
    /// underneath with the parameters inside. As constant time as that
    /// agreement's `init`.
    fn init(&mut self, params: &UkmParams<P>) -> Result<(), A::Error> {
        self.initialized = false;
        self.agreement.init(params.params())?;
        self.ukm = params.ukm().to_vec();
        self.initialized = true;
        Ok(())
    }
}

impl<A, K> Agreement for AgreementWithKdf<A, K>
where
    A: Agreement,
    K: Kdf + for<'a> KdfInit<EcdhKekParamsRef<'a>, Error = Infallible>,
{
    type PublicKey = A::PublicKey;
    type Error = AgreementWithKdfError<A::Error, <K as Kdf>::Error>;

    /// The length of the derived key: `key_size / 8` bytes. Constant time.
    fn agreement_size(&self) -> usize {
        (self.key_size / 8) as usize
    }

    /// Bouncy Castle's `CalculateAgreementWithKdf`: the agreement underneath
    /// writes Z at its fixed length, the KDF is initialized with
    /// `EcdhKekParamsRef::with_extra_info(key_info, key_size, Z, UKM)`, and the
    /// key goes into the front of `output`. Z is wiped after use. As constant
    /// time in Z as the agreement and the KDF are.
    fn calculate_agreement(
        &self,
        public_key: &A::PublicKey,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(AgreementWithKdfError::NotInitialized);
        }
        let output = output
            .get_mut(..self.agreement_size())
            .ok_or(AgreementWithKdfError::BufferTooSmall)?;
        let mut z = Zeroizing::new(vec![0u8; self.agreement.agreement_size()]);
        self.agreement
            .calculate_agreement(public_key, &mut z)
            .map_err(AgreementWithKdfError::Agreement)?;

        let mut kdf = self.kdf.borrow_mut();
        let Ok(()) = kdf.init(&EcdhKekParamsRef::with_extra_info(
            &self.key_info,
            self.key_size,
            &z,
            &self.ukm,
        ));
        kdf.generate_bytes(output)
            .map_err(AgreementWithKdfError::Kdf)?;
        Ok(())
    }
}
