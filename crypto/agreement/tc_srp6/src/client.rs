use crate::group::Group;
use crate::utilities::{self, evidence_matches, widened};
use crate::{Srp6Error, Srp6GroupParameters};
use alloc::vec::Vec;
use rand_core::CryptoRng;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_modular::PaddedMontyForm;
use tc_zeroize::Zeroizing;

/// BC 的 `Srp6Client`：SRP-6a 的 client 端，照 Thomas Wu 2002 年論文最佳化的訊息順序。
/// 有狀態，每次驗證都要重新 `init`。
///
/// BC 把私密指數加上 N - 1 的隨機倍數，再交給變動時間的 `ModPow`；這裡的模冪本身就是
/// 常數時間，所以不做這層遮蔽，亂數只用來抽 a。
pub struct Srp6Client<D, R> {
    digest: D,
    rng: R,
    state: Option<ClientState>,
}

/// `init` 之後的狀態：各值在對應的步驟算出，私密的部分 drop 時清除。
struct ClientState {
    group: Group,
    x: Option<Zeroizing<PaddedBigUint>>,
    private_a: Option<Zeroizing<PaddedBigUint>>,
    public_a: Option<PaddedBigUint>,
    b: Option<PaddedBigUint>,
    s: Option<Zeroizing<PaddedBigUint>>,
    m1: Option<Vec<u8>>,
    m2: Option<Vec<u8>>,
}

impl<D: Digest, R> Srp6Client<D, R> {
    /// 以 `digest` 為雜湊、以 `rng` 抽 a 的 client，尚未 `init`。常數時間。
    pub fn new(digest: D, rng: R) -> Self {
        Self {
            digest,
            rng,
            state: None,
        }
    }

    /// BC 的 `Init`：開始一次新的驗證，丟掉上一次的狀態。檢查 N 是大於 3 的奇數、g 在
    /// `[2, N - 2]`。變動時間：只依公開的群組分支。
    pub fn init(&mut self, group: &Srp6GroupParameters) -> Result<(), Srp6Error> {
        self.state = None;
        self.state = Some(ClientState {
            group: Group::new(group)?,
            x: None,
            private_a: None,
            public_a: None,
            b: None,
            s: None,
            m1: None,
            m2: None,
        });
        Ok(())
    }

    /// BC 的 `GenerateClientCredentials`：由鹽、身分與密碼算出 x，抽私密值 a，回傳要寄給
    /// server 的 A = g^a mod N。對密碼、x 與 a 是常數時間，只要雜湊本身是；只有被丟棄的
    /// a 候選值多少反映在時間上。
    pub fn generate_client_credentials(
        &mut self,
        salt: &[u8],
        identity: &[u8],
        password: &[u8],
    ) -> Result<PaddedBigUint, Srp6Error>
    where
        R: CryptoRng,
    {
        let state = self.state.as_ref().ok_or(Srp6Error::NotInitialized)?;
        let private_a = utilities::generate_private_value(&state.group.n, &mut self.rng);
        self.credentials_with(salt, identity, password, private_a)
    }

    /// 以指定的 a 做 [`generate_client_credentials`](Self::generate_client_credentials)，
    /// 對應 BC 測試覆寫的 `SelectPrivateValue`。對密碼、x 與 a 是常數時間，只要雜湊本身是。
    pub(crate) fn credentials_with(
        &mut self,
        salt: &[u8],
        identity: &[u8],
        password: &[u8],
        private_a: PaddedBigUint,
    ) -> Result<PaddedBigUint, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let private_a = Zeroizing::new(private_a);
        let x = Zeroizing::new(utilities::calculate_x(
            &mut self.digest,
            salt,
            identity,
            password,
        ));
        let power = Zeroizing::new(
            PaddedMontyForm::new(&state.group.g, &state.group.monty).pow(&private_a),
        );
        let public_a = power.retrieve();
        state.x = Some(x);
        state.private_a = Some(private_a);
        state.public_a = Some(public_a.clone());
        Ok(public_a)
    }

    /// BC 的 `CalculateSecret`：檢查 server 的 B，算出共享秘密
    /// S = (B - k·g^x)^(a + u·x) mod N 並回傳，呼叫端用完要清除。要先
    /// [`generate_client_credentials`](Self::generate_client_credentials)。對 x、a 與 S
    /// 是常數時間；檢查公開的 B 依值分支。
    pub fn calculate_secret(
        &mut self,
        server_b: &PaddedBigUint,
    ) -> Result<PaddedBigUint, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let (Some(x), Some(private_a), Some(public_a)) =
            (&state.x, &state.private_a, &state.public_a)
        else {
            return Err(Srp6Error::MissingValues);
        };
        let b = utilities::validate_public_value(&state.group.n, server_b)?;
        let s = client_secret(&mut self.digest, &state.group, x, private_a, public_a, &b);
        state.b = Some(b);
        state.s = Some(Zeroizing::new(s.clone()));
        Ok(s)
    }

    /// BC 的 `CalculateClientEvidenceMessage`：M1 = H(PAD(A) | PAD(B) | PAD(S))，寄給
    /// server。要先 [`calculate_secret`](Self::calculate_secret)。對 S 是常數時間，只要
    /// 雜湊本身是。
    pub fn calculate_client_evidence_message(&mut self) -> Result<Vec<u8>, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let (Some(public_a), Some(b), Some(s)) = (&state.public_a, &state.b, &state.s) else {
            return Err(Srp6Error::MissingValues);
        };
        let m1 = utilities::calculate_m1(&mut self.digest, &state.group.n, public_a, b, s);
        state.m1 = Some(m1.clone());
        Ok(m1)
    }

    /// BC 的 `VerifyServerEvidenceMessage`：server 的 M2 是否正確，正確才記下。要先
    /// [`calculate_client_evidence_message`](Self::calculate_client_evidence_message)。
    /// 同 BC 以整數比較，接受去掉前導零的編碼。對 S 與 M2 是常數時間；只依公開的長度分支。
    pub fn verify_server_evidence_message(&mut self, server_m2: &[u8]) -> Result<bool, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let (Some(public_a), Some(m1), Some(s)) = (&state.public_a, &state.m1, &state.s) else {
            return Err(Srp6Error::MissingValues);
        };
        let expected = utilities::calculate_m2(&mut self.digest, &state.group.n, public_a, m1, s);
        if !evidence_matches(&expected, server_m2) {
            return Ok(false);
        }
        state.m2 = Some(expected);
        Ok(true)
    }

    /// BC 的 `CalculateSessionKey`：雙方互相驗證後的工作階段金鑰 K = H(PAD(S))，呼叫端用完
    /// 要清除。要先驗過 M2。對 S 是常數時間，只要雜湊本身是。
    pub fn calculate_session_key(&mut self) -> Result<Vec<u8>, Srp6Error> {
        let state = self.state.as_ref().ok_or(Srp6Error::NotInitialized)?;
        let (Some(s), Some(_), Some(_)) = (&state.s, &state.m1, &state.m2) else {
            return Err(Srp6Error::MissingValues);
        };
        Ok(utilities::calculate_key(
            &mut self.digest,
            &state.group.n,
            s,
        ))
    }
}

/// S = (B - k·g^x)^(a + u·x) mod N，指數在整數上算，不取模。對 x 與 a 是常數時間：乘法
/// 與模冪只依寬度，中間值會清除；k 與 u 由公開值算出。
fn client_secret<D: Digest>(
    digest: &mut D,
    group: &Group,
    x: &PaddedBigUint,
    private_a: &PaddedBigUint,
    public_a: &PaddedBigUint,
    b: &PaddedBigUint,
) -> PaddedBigUint {
    let k = utilities::calculate_k(digest, &group.n, &group.g);
    let u = utilities::calculate_u(digest, &group.n, public_a, b);
    // u·x + a 放得下的寬度，乘法與加法都不會溢位。
    let width = (u.as_limbs().len() + x.as_limbs().len()).max(private_a.as_limbs().len()) + 1;
    let mut exponent = Zeroizing::new(widened(&u, width));
    *exponent *= x;
    *exponent += private_a;

    let monty = &group.monty;
    let gx = Zeroizing::new(PaddedMontyForm::new(&group.g, monty).pow(x));
    let kgx = Zeroizing::new(PaddedMontyForm::new(&k, monty) * &*gx);
    let base = Zeroizing::new(PaddedMontyForm::new(b, monty) - &*kgx);
    let power = Zeroizing::new(base.pow(&exponent));
    power.retrieve()
}
