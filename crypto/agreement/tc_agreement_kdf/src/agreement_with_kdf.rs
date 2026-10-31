use crate::{AgreementWithKdfError, UkmParams};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::convert::Infallible;
use tc_agreement::{Agreement, AgreementInit};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_ecdh_kek::EcdhKekParamsRef;
use tc_kdf::{Kdf, KdfInit};
use tc_zeroize::Zeroizing;

/// BC 的 `ECDHWithKdfBasicAgreement`、`ECDHCWithKdfBasicAgreement` 與
/// `ECMqvWithKdfBasicAgreement`，三個類別只差在底層協商，這裡合成一個泛型：先以 `A`
/// 協商出 Z，再以 KDF `K`（通常是 `tc_ecdh_kek` 的 `EcdhKek`）從 Z、`key_info`、
/// `key_size` 與 UKM 導出 `key_size / 8` 位元組的金鑰。
///
/// BC 以 `GeneratorUtilities.GetDefaultKeySize` 依 `key_info` 查金鑰長度；這裡由呼叫端給。
/// BC 把導出的金鑰轉成整數回傳，前導的零會被去掉；這裡寫成固定長度。
pub struct AgreementWithKdf<A, K> {
    agreement: A,
    kdf: RefCell<K>,
    key_info: AlgorithmIdentifier,
    key_size: u32,
    ukm: Vec<u8>,
    initialized: bool,
}

impl<A, K> AgreementWithKdf<A, K> {
    /// 以 `agreement` 協商、以 `kdf` 導出 `key_size` 位元、給 `key_info` 用的金鑰，尚未
    /// `init`。常數時間。
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

    /// BC 的 `Init`：保存 UKM，以裡面的參數初始化底層協商。常數時間程度同底層協商的
    /// `init`。
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

    /// 導出的金鑰長度：`key_size / 8` 位元組。常數時間。
    fn agreement_size(&self) -> usize {
        (self.key_size / 8) as usize
    }

    /// BC 的 `CalculateAgreementWithKdf`：底層協商寫出固定長度的 Z，以
    /// `EcdhKekParamsRef::with_extra_info(key_info, key_size, Z, UKM)` 初始化 KDF，導出
    /// 金鑰寫入 `output` 的前段。Z 用畢清除。對 Z 的常數時間程度同底層協商與 KDF。
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
