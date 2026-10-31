use crate::group::Group;
use crate::utilities;
use crate::{Srp6Error, Srp6GroupParameters};
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_modular::PaddedMontyForm;
use tc_zeroize::Zeroizing;

/// BC 的 `Srp6VerifierGenerator`：為使用者產生 server 要保存的驗證值 v = g^x mod N。之後
/// 驗證時要用同一種雜湊，工作階段金鑰的長度也由它決定。
///
/// BC 為了遮蔽變動時間的 `ModPow` 而收一個亂數來源；這裡的模冪本身就是常數時間，不需要。
pub struct Srp6VerifierGenerator<D> {
    digest: D,
    group: Option<Group>,
}

impl<D: Digest> Srp6VerifierGenerator<D> {
    /// 以 `digest` 為雜湊的產生器，尚未 `init`。常數時間。
    pub fn new(digest: D) -> Self {
        Self {
            digest,
            group: None,
        }
    }

    /// BC 的 `Init`：設定群組，檢查 N 是大於 3 的奇數、g 在 `[2, N - 2]`。變動時間：只依
    /// 公開的群組分支。
    pub fn init(&mut self, group: &Srp6GroupParameters) -> Result<(), Srp6Error> {
        self.group = None;
        self.group = Some(Group::new(group)?);
        Ok(())
    }

    /// BC 的 `GenerateVerifier`：由鹽、身分與密碼算出 x，回傳 v = g^x mod N。鹽一般要夠長
    /// 且隨機。對密碼與 x 是常數時間，只要雜湊本身是；x 會清除。
    pub fn generate_verifier(
        &mut self,
        salt: &[u8],
        identity: &[u8],
        password: &[u8],
    ) -> Result<PaddedBigUint, Srp6Error> {
        let group = self.group.as_ref().ok_or(Srp6Error::NotInitialized)?;
        let x = Zeroizing::new(utilities::calculate_x(
            &mut self.digest,
            salt,
            identity,
            password,
        ));
        let power = Zeroizing::new(PaddedMontyForm::new(&group.g, &group.monty).pow(&x));
        Ok(power.retrieve())
    }
}
