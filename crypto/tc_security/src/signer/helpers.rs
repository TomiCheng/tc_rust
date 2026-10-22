use tc_signer::{Signer, SignerInit};

use super::AnySigner;
use crate::AnyError;
use crate::params::AnyParams;

/// 用 `private_key` 初始化後簽 `message`，回傳新配置的簽章。
pub fn sign(
    signer: &mut AnySigner,
    private_key: &AnyParams,
    message: &[u8],
) -> Result<Vec<u8>, AnyError> {
    signer.init(private_key)?;
    signer.update(message)?;
    let mut signature = vec![0; signer.max_signature_size()];
    let written = signer.generate_signature(&mut signature)?;
    signature.truncate(written);
    Ok(signature)
}

/// 用 `public_key` 初始化後，驗 `signature` 是不是 `message` 的簽章。
pub fn verify(
    signer: &mut AnySigner,
    public_key: &AnyParams,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, AnyError> {
    signer.init(public_key)?;
    signer.update(message)?;
    signer.verify_signature(signature)
}
