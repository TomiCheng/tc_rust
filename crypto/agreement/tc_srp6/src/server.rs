use crate::group::Group;
use crate::utilities::{self, evidence_matches};
use crate::{Srp6Error, Srp6GroupParameters};
use alloc::vec::Vec;
use rand_core::CryptoRng;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_modular::PaddedMontyForm;
use tc_zeroize::Zeroizing;

/// BC 的 `Srp6Server`：SRP-6a 的 server 端，照 Thomas Wu 2002 年論文最佳化的訊息順序。
/// 有狀態，每次驗證都要重新 `init`。
///
/// BC 把私密指數加上 N - 1 的隨機倍數，再交給變動時間的 `ModPow`，並註明 v 還沒保護；
/// 這裡的模冪本身就是常數時間，對 b 與 v 都是，所以不做這層遮蔽，亂數只用來抽 b。
pub struct Srp6Server<D, R> {
    digest: D,
    rng: R,
    state: Option<ServerState>,
}

/// `init` 之後的狀態：各值在對應的步驟算出，私密的部分 drop 時清除。
struct ServerState {
    group: Group,
    v: Zeroizing<PaddedBigUint>,
    a: Option<PaddedBigUint>,
    private_b: Option<Zeroizing<PaddedBigUint>>,
    public_b: Option<PaddedBigUint>,
    s: Option<Zeroizing<PaddedBigUint>>,
    m1: Option<Vec<u8>>,
    m2: Option<Vec<u8>>,
}

impl<D: Digest, R> Srp6Server<D, R> {
    /// 以 `digest` 為雜湊、以 `rng` 抽 b 的 server，尚未 `init`。常數時間。
    pub fn new(digest: D, rng: R) -> Self {
        Self {
            digest,
            rng,
            state: None,
        }
    }

    /// BC 的 `Init`：以使用者的驗證值 v 開始一次新的驗證，丟掉上一次的狀態。檢查 N 是
    /// 大於 3 的奇數、g 在 `[2, N - 2]`；v 不檢查，同 BC。變動時間：只依公開的群組分支，
    /// v 只是複製。
    pub fn init(
        &mut self,
        group: &Srp6GroupParameters,
        verifier: &PaddedBigUint,
    ) -> Result<(), Srp6Error> {
        self.state = None;
        self.state = Some(ServerState {
            group: Group::new(group)?,
            v: Zeroizing::new(verifier.clone()),
            a: None,
            private_b: None,
            public_b: None,
            s: None,
            m1: None,
            m2: None,
        });
        Ok(())
    }

    /// BC 的 `GenerateServerCredentials`：抽私密值 b，回傳要寄給 client 的
    /// B = (k·v + g^b) mod N。對 v 與 b 是常數時間；只有被丟棄的 b 候選值多少反映在時間上。
    pub fn generate_server_credentials(&mut self) -> Result<PaddedBigUint, Srp6Error>
    where
        R: CryptoRng,
    {
        let state = self.state.as_ref().ok_or(Srp6Error::NotInitialized)?;
        let private_b = utilities::generate_private_value(&state.group.n, &mut self.rng);
        self.credentials_with(private_b)
    }

    /// 以指定的 b 做 [`generate_server_credentials`](Self::generate_server_credentials)，
    /// 對應 BC 測試覆寫的 `SelectPrivateValue`。對 v 與 b 是常數時間。
    pub(crate) fn credentials_with(
        &mut self,
        private_b: PaddedBigUint,
    ) -> Result<PaddedBigUint, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let private_b = Zeroizing::new(private_b);
        let group = &state.group;
        let monty = &group.monty;
        let k = utilities::calculate_k(&mut self.digest, &group.n, &group.g);
        let v = Zeroizing::new(PaddedMontyForm::new(&state.v, monty));
        let kv = Zeroizing::new(PaddedMontyForm::new(&k, monty) * &*v);
        let gb = Zeroizing::new(PaddedMontyForm::new(&group.g, monty).pow(&private_b));
        let public_b = (&*kv + &*gb).retrieve();
        state.private_b = Some(private_b);
        state.public_b = Some(public_b.clone());
        Ok(public_b)
    }

    /// BC 的 `CalculateSecret`：檢查 client 的 A，算出共享秘密 S = (A·v^u)^b mod N 並
    /// 回傳，呼叫端用完要清除。要先
    /// [`generate_server_credentials`](Self::generate_server_credentials)。對 v、b 與 S
    /// 是常數時間；檢查公開的 A 依值分支。
    pub fn calculate_secret(
        &mut self,
        client_a: &PaddedBigUint,
    ) -> Result<PaddedBigUint, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let (Some(private_b), Some(public_b)) = (&state.private_b, &state.public_b) else {
            return Err(Srp6Error::MissingValues);
        };
        let a = utilities::validate_public_value(&state.group.n, client_a)?;
        let group = &state.group;
        let monty = &group.monty;
        let u = utilities::calculate_u(&mut self.digest, &group.n, &a, public_b);
        let v = Zeroizing::new(PaddedMontyForm::new(&state.v, monty));
        let vu = Zeroizing::new(v.pow(&u));
        let base = Zeroizing::new(PaddedMontyForm::new(&a, monty) * &*vu);
        let power = Zeroizing::new(base.pow(private_b));
        let s = power.retrieve();
        state.a = Some(a);
        state.s = Some(Zeroizing::new(s.clone()));
        Ok(s)
    }

    /// BC 的 `VerifyClientEvidenceMessage`：client 的 M1 是否正確，正確才記下。要先
    /// [`calculate_secret`](Self::calculate_secret)。同 BC 以整數比較，接受去掉前導零的
    /// 編碼。對 S 與 M1 是常數時間；只依公開的長度分支。
    pub fn verify_client_evidence_message(&mut self, client_m1: &[u8]) -> Result<bool, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let (Some(a), Some(public_b), Some(s)) = (&state.a, &state.public_b, &state.s) else {
            return Err(Srp6Error::MissingValues);
        };
        let expected = utilities::calculate_m1(&mut self.digest, &state.group.n, a, public_b, s);
        if !evidence_matches(&expected, client_m1) {
            return Ok(false);
        }
        state.m1 = Some(expected);
        Ok(true)
    }

    /// BC 的 `CalculateServerEvidenceMessage`：M2 = H(PAD(A) | PAD(M1) | PAD(S))，寄給
    /// client。要先驗過 M1。對 S 是常數時間，只要雜湊本身是。
    pub fn calculate_server_evidence_message(&mut self) -> Result<Vec<u8>, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let (Some(a), Some(m1), Some(s)) = (&state.a, &state.m1, &state.s) else {
            return Err(Srp6Error::MissingValues);
        };
        let m2 = utilities::calculate_m2(&mut self.digest, &state.group.n, a, m1, s);
        state.m2 = Some(m2.clone());
        Ok(m2)
    }

    /// BC 的 `CalculateSessionKey`：雙方互相驗證後的工作階段金鑰 K = H(PAD(S))，呼叫端用完
    /// 要清除。要先算出 M2。對 S 是常數時間，只要雜湊本身是。
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
