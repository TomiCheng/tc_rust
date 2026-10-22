use tc_agreement::{Agreement, AgreementInit};

use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

// 公鑰與錯誤都已經換成 AnyParams 與 AnyError，合成一個 trait 才能放進同一個 dyn
trait InnerAnyAgreement:
    Agreement<PublicKey = AnyParams, Error = AnyError> + AgreementInit<AnyParams, Error = AnyError>
{
}

impl<T> InnerAnyAgreement for T where
    T: Agreement<PublicKey = AnyParams, Error = AnyError>
        + AgreementInit<AnyParams, Error = AnyError>
{
}

type PrivateKeyOf<K> = fn(&AnyParams) -> Option<&K>;
type PublicKeyOf<T> = fn(&AnyParams) -> Option<&<T as Agreement>::PublicKey>;

/// 包住具體的 agreement：金鑰從 `AnyParams` 取出具體型別，錯誤換成 `AnyError`。
/// 具體 agreement 收的是自己的金鑰型別，所以每個演算法要給取出金鑰的函式。
#[allow(
    dead_code,
    reason = "所有 agreement 的 feature 都關掉時，沒有 agreement"
)]
struct AgreementWrapper<T: Agreement, K> {
    agreement: T,
    private_key: PrivateKeyOf<K>,
    public_key: PublicKeyOf<T>,
}

impl<T, K> AgreementInit<AnyParams> for AgreementWrapper<T, K>
where
    T: Agreement + AgreementInit<K>,
    <T as AgreementInit<K>>::Error: Send + Sync + 'static,
{
    type Error = AnyError;

    fn init(&mut self, params: &AnyParams) -> Result<(), AnyError> {
        let key =
            (self.private_key)(params).ok_or_else(|| AnyError::new(SecurityError::WrongParams))?;
        self.agreement.init(key).map_err(AnyError::new)
    }
}

impl<T, K> Agreement for AgreementWrapper<T, K>
where
    T: Agreement,
    <T as Agreement>::Error: Send + Sync + 'static,
{
    type PublicKey = AnyParams;
    type Error = AnyError;

    fn agreement_size(&self) -> usize {
        self.agreement.agreement_size()
    }

    fn calculate_agreement(
        &self,
        public_key: &AnyParams,
        output: &mut [u8],
    ) -> Result<(), AnyError> {
        let key = (self.public_key)(public_key)
            .ok_or_else(|| AnyError::new(SecurityError::WrongParams))?;
        self.agreement
            .calculate_agreement(key, output)
            .map_err(AnyError::new)
    }
}

/// 執行時才決定的 key agreement；私鑰與對方的公鑰都用 [`AnyParams`] 傳。
pub struct AnyAgreement(Box<dyn InnerAnyAgreement>);

impl AnyAgreement {
    // 給表用：私鑰與公鑰各給一個從 AnyParams 取出具體型別的函式，種類不對時回傳 None
    #[allow(
        dead_code,
        reason = "所有 agreement 的 feature 都關掉時，沒有 agreement"
    )]
    pub(super) fn new<T, K>(
        agreement: T,
        private_key: PrivateKeyOf<K>,
        public_key: PublicKeyOf<T>,
    ) -> Self
    where
        T: Agreement + AgreementInit<K> + 'static,
        K: 'static,
        <T as Agreement>::Error: Send + Sync + 'static,
        <T as AgreementInit<K>>::Error: Send + Sync + 'static,
    {
        Self(Box::new(AgreementWrapper {
            agreement,
            private_key,
            public_key,
        }))
    }
}

impl AgreementInit<AnyParams> for AnyAgreement {
    type Error = AnyError;

    fn init(&mut self, params: &AnyParams) -> Result<(), AnyError> {
        self.0.init(params)
    }
}

impl Agreement for AnyAgreement {
    type PublicKey = AnyParams;
    type Error = AnyError;

    fn agreement_size(&self) -> usize {
        self.0.agreement_size()
    }

    fn calculate_agreement(
        &self,
        public_key: &AnyParams,
        output: &mut [u8],
    ) -> Result<(), AnyError> {
        self.0.calculate_agreement(public_key, output)
    }
}
