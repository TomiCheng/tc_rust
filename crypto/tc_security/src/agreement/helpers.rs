use tc_agreement::{Agreement, AgreementInit};
use tc_zeroize::Zeroize;

use super::AnyAgreement;
use crate::AnyError;
use crate::params::AnyParams;

/// 用 `private_key` 初始化後，算出與 `public_key` 的共享秘密，回傳新配置的結果。
pub fn calculate_agreement(
    agreement: &mut AnyAgreement,
    private_key: &AnyParams,
    public_key: &AnyParams,
) -> Result<Vec<u8>, AnyError> {
    agreement.init(private_key)?;
    let mut secret = vec![0; agreement.agreement_size()];
    match agreement.calculate_agreement(public_key, &mut secret) {
        Ok(()) => Ok(secret),
        // 失敗時輸出可能留著部分結果，丟掉前先清除
        Err(error) => {
            secret.zeroize();
            Err(error)
        }
    }
}
