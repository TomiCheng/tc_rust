use crate::DhAgreementError;
use tc_agreement::{Agreement, AgreementInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_constant_time::ConstantTimeEq;
use tc_dh_key::{DhPrivateKey, DhPublicKey};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

/// BC 的 `DHBasicAgreement`：共享秘密是 y^x mod p，y 是對方的公鑰、x 是自己的私鑰。
///
/// 結果寫成 p 的位元組數、前面補零的大端序，同 `tc_agreement` 的約定；BC 回傳整數，
/// 前導的零會被去掉。
pub struct DhBasicAgreement {
    state: Option<(DhPrivateKey, PaddedMontyParams)>,
}

impl DhBasicAgreement {
    /// 尚未 `init` 的協商。常數時間。
    pub fn new() -> Self {
        Self { state: None }
    }
}

impl Default for DhBasicAgreement {
    fn default() -> Self {
        Self::new()
    }
}

impl AgreementInit<DhPrivateKey> for DhBasicAgreement {
    type Error = DhAgreementError;

    /// 保存私鑰的複本，drop 時清除 x；以 `DhParameters::validate` 檢查參數，並為 p 建好
    /// Montgomery 參數。變動時間：只依公開的參數分支。
    fn init(&mut self, key: &DhPrivateKey) -> Result<(), DhAgreementError> {
        self.state = None;
        key.params()
            .validate()
            .map_err(DhAgreementError::InvalidParameters)?;
        let p = Odd::new(key.params().p().clone()).ok_or(DhAgreementError::InvalidParameters(
            tc_dh_key::DhError::InvalidModulus,
        ))?;
        self.state = Some((key.clone(), PaddedMontyParams::new(p)));
        Ok(())
    }
}

impl Agreement for DhBasicAgreement {
    type PublicKey = DhPublicKey;
    type Error = DhAgreementError;

    /// BC 的 `GetFieldSize`：p 的位元組數。`init` 之前呼叫會 panic。常數時間。
    fn agreement_size(&self) -> usize {
        let (key, _) = self.state.as_ref().expect("the agreement is initialized");
        (key.params().p().bits() as usize).div_ceil(8)
    }

    /// BC 的 `CalculateAgreement`：對方的參數要相同，公鑰要通過 `DhPublicKey::validate`
    /// （在 `[2, p - 2]`、有 q 時在子群裡），結果不得為 1。檢查公鑰依公開的值分支；
    /// y^x 對 x 是常數時間，結果是否為 1 以常數時間比較，只由錯誤透露。
    fn calculate_agreement(
        &self,
        public_key: &DhPublicKey,
        output: &mut [u8],
    ) -> Result<(), DhAgreementError> {
        let (key, monty) = self
            .state
            .as_ref()
            .ok_or(DhAgreementError::NotInitialized)?;
        if public_key.params() != key.params() {
            return Err(DhAgreementError::WrongParameters);
        }
        public_key
            .validate()
            .map_err(DhAgreementError::InvalidPublicKey)?;
        let size = self.agreement_size();
        let output = output
            .get_mut(..size)
            .ok_or(DhAgreementError::BufferTooSmall)?;

        let power = Zeroizing::new(PaddedMontyForm::new(public_key.y(), monty).pow(key.x()));
        let shared = Zeroizing::new(power.retrieve());
        if shared.ct_eq(&PaddedBigUint::from(1u8)).unwrap_u8() == 1 {
            return Err(DhAgreementError::InvalidAgreement);
        }
        write_be(&shared, output);
        Ok(())
    }
}

/// `value` 以大端序寫滿 `output`，前面補零；value 必須放得下。對值是常數時間：只依寬度
/// 決定讀寫的位置。
pub(crate) fn write_be(value: &PaddedBigUint, output: &mut [u8]) {
    let mut bytes = ArrayEncoding::<u8>::to_be(value);
    let length = output.len().min(bytes.len());
    output.fill(0);
    let start = output.len() - length;
    output[start..].copy_from_slice(&bytes[bytes.len() - length..]);
    bytes.zeroize();
}
