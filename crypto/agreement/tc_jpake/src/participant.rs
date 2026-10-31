use crate::utilities::{
    Domain, calculate_s, mac_tag, validate_mac_tag, validate_not_one,
    validate_participant_ids_differ, validate_participant_ids_equal,
};
use crate::{JPakeError, JPakeParams, JPakeRound1Payload, JPakeRound2Payload, JPakeRound3Payload};
use alloc::string::String;
use rand_core::CryptoRng;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_sha::Sha256Digest;
use tc_zeroize::Zeroizing;

/// `JPakeParticipant` 的進度，依交換的順序排列；BC 的 `STATE_*` 常數。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JPakeState {
    /// 剛 `init`。
    Initialized,
    /// 已產生第一輪的酬載。
    Round1Created,
    /// 已驗證對方第一輪的酬載。
    Round1Validated,
    /// 已產生第二輪的酬載。
    Round2Created,
    /// 已驗證對方第二輪的酬載。
    Round2Validated,
    /// 已算出協商結果。
    KeyCalculated,
    /// 已產生第三輪的酬載。
    Round3Created,
    /// 已驗證對方第三輪的酬載。
    Round3Validated,
}

/// BC 的 `JPakeParticipant`：J-PAKE 交換的一方。雙方只共有一個密碼，各自依序產生並寄出
/// 第一、二輪的酬載、驗證對方的，再算出同一份協商結果；第三輪可另外確認對方用了同一個
/// 密碼。協商結果要再經過 KDF 才能當作工作階段金鑰。
///
/// 每一步只能做一次，且要在前一步之後，否則回傳 [`JPakeError::RepeatedStep`] 或
/// [`JPakeError::PrematureStep`]；BC 在第一輪酬載建立前就驗證對方的酬載時會留下空值而崩潰，
/// 這裡改回傳後者。雜湊預設是 SHA-256。
pub struct JPakeParticipant<R, D = Sha256Digest> {
    digest: D,
    rng: R,
    session: Option<Session>,
}

/// `init` 後的狀態。x1 只用在第一輪，不保存。
struct Session {
    participant_id: String,
    domain: Domain,
    state: JPakeState,
    s: Option<Zeroizing<PaddedBigUint>>,
    x2: Option<Zeroizing<PaddedBigUint>>,
    gx1: Option<PaddedBigUint>,
    gx2: Option<PaddedBigUint>,
    partner_participant_id: Option<String>,
    gx3: Option<PaddedBigUint>,
    gx4: Option<PaddedBigUint>,
    b: Option<PaddedBigUint>,
}

impl<R: CryptoRng> JPakeParticipant<R, Sha256Digest> {
    /// 以 SHA-256 為雜湊（BC 的預設）、尚未 `init` 的參與者。常數時間。
    pub fn new(rng: R) -> Self {
        Self::with_digest(Sha256Digest::new(), rng)
    }
}

impl<R: CryptoRng, D: Digest + Clone> JPakeParticipant<R, D> {
    /// 以 `digest` 為雜湊、`rng` 為亂數來源，尚未 `init` 的參與者。常數時間。
    pub fn with_digest(digest: D, rng: R) -> Self {
        Self {
            digest,
            rng,
            session: None,
        }
    }

    /// BC 建構子的檢查：密碼不得為空，群組要通過 `JPakePrimeOrderGroup::validate`，密碼
    /// 模 q 不得為 0（BC 到第二輪才檢查）。之後回到 [`JPakeState::Initialized`]。
    /// 變動時間：只依公開的群組分支；密碼取模不依它的值，只有長度反映在時間上。
    pub fn init(&mut self, params: &JPakeParams) -> Result<(), JPakeError> {
        self.session = None;
        if params.password().is_empty() {
            return Err(JPakeError::EmptyPassword);
        }
        params.group().validate(&mut self.rng)?;
        let domain = Domain::new(params.group())?;
        let s = calculate_s(domain.q(), params.password())?;
        self.session = Some(Session {
            participant_id: params.participant_id().into(),
            domain,
            state: JPakeState::Initialized,
            s: Some(s),
            x2: None,
            gx1: None,
            gx2: None,
            partner_participant_id: None,
            gx3: None,
            gx4: None,
            b: None,
        });
        Ok(())
    }

    /// 目前的進度；`init` 之前是 `None`。常數時間。
    pub fn state(&self) -> Option<JPakeState> {
        self.session.as_ref().map(|session| session.state)
    }

    /// BC 的 `CreateRound1PayloadToSend`：x1 在 `[0, q − 1]`、x2 在 `[1, q − 1]` 中隨機取，
    /// 寄出 g^x1、g^x2 與兩者的零知識證明。對 x1、x2 是常數時間。
    pub fn create_round1_payload_to_send(&mut self) -> Result<JPakeRound1Payload, JPakeError> {
        let Self {
            digest,
            rng,
            session,
        } = self;
        let session = session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::Round1Created, JPakeState::Initialized)?;
        let domain = &session.domain;
        let x1 = domain.generate_x1(rng);
        let x2 = domain.generate_x2(rng);
        let gx1 = domain.power(domain.g(), &x1);
        let gx2 = domain.power(domain.g(), &x2);
        let id = &session.participant_id;
        let proof1 = domain.prove(domain.g(), &gx1, &x1, id, digest, rng);
        let proof2 = domain.prove(domain.g(), &gx2, &x2, id, digest, rng);
        let payload = JPakeRound1Payload::new(id, gx1.clone(), gx2.clone(), proof1, proof2);
        session.x2 = Some(x2);
        session.gx1 = Some(gx1);
        session.gx2 = Some(gx2);
        session.state = JPakeState::Round1Created;
        Ok(payload)
    }

    /// BC 的 `ValidateRound1PayloadReceived`：對方的 ID 要與自己不同、g^x4 不得為 1，兩個
    /// 零知識證明都要成立。變動時間：只用於公開值。
    pub fn validate_round1_payload_received(
        &mut self,
        payload: &JPakeRound1Payload,
    ) -> Result<(), JPakeError> {
        let Self {
            digest, session, ..
        } = self;
        let session = session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::Round1Validated, JPakeState::Initialized)?;
        let domain = &session.domain;
        let partner = payload.participant_id();
        validate_participant_ids_differ(&session.participant_id, partner)?;
        validate_not_one(payload.gx2(), JPakeError::GxIsOne)?;
        domain.verify(
            domain.g(),
            payload.gx1(),
            payload.knowledge_proof_for_x1(),
            partner,
            digest,
        )?;
        domain.verify(
            domain.g(),
            payload.gx2(),
            payload.knowledge_proof_for_x2(),
            partner,
            digest,
        )?;
        session.partner_participant_id = Some(partner.into());
        session.gx3 = Some(payload.gx1().clone());
        session.gx4 = Some(payload.gx2().clone());
        session.state = JPakeState::Round1Validated;
        Ok(())
    }

    /// BC 的 `CreateRound2PayloadToSend`：寄出 A = (g^x1·g^x3·g^x4)^(x2·s) 與 x2·s 的零知識
    /// 證明，生成元是 g^(x1 + x3 + x4)。對 x2 與 s 是常數時間。
    pub fn create_round2_payload_to_send(&mut self) -> Result<JPakeRound2Payload, JPakeError> {
        let Self {
            digest,
            rng,
            session,
        } = self;
        let session = session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::Round2Created, JPakeState::Round1Validated)?;
        let domain = &session.domain;
        let ga = domain.product(
            required(&session.gx1)?,
            required(&session.gx3)?,
            required(&session.gx4)?,
        );
        let x2s = domain.x2s(required(&session.x2)?, required(&session.s)?);
        let a = domain.power(&ga, &x2s);
        let proof = domain.prove(&ga, &a, &x2s, &session.participant_id, digest, rng);
        session.state = JPakeState::Round2Created;
        Ok(JPakeRound2Payload::new(&session.participant_id, a, proof))
    }

    /// BC 的 `ValidateRound2PayloadReceived`：酬載要來自第一輪的對象，生成元
    /// g^(x3 + x1 + x2) 不得為 1，x4·s 的零知識證明要成立。變動時間：只用於公開值。
    pub fn validate_round2_payload_received(
        &mut self,
        payload: &JPakeRound2Payload,
    ) -> Result<(), JPakeError> {
        let Self {
            digest, session, ..
        } = self;
        let session = session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::Round2Validated, JPakeState::Round1Validated)?;
        let domain = &session.domain;
        let gb = domain.product(
            required(&session.gx3)?,
            required(&session.gx1)?,
            required(&session.gx2)?,
        );
        let partner = payload.participant_id();
        validate_participant_ids_differ(&session.participant_id, partner)?;
        validate_participant_ids_equal(required(&session.partner_participant_id)?, partner)?;
        validate_not_one(&gb, JPakeError::GaIsOne)?;
        domain.verify(
            &gb,
            payload.a(),
            payload.knowledge_proof_for_x2s(),
            partner,
            digest,
        )?;
        session.b = Some(payload.a().clone());
        session.state = JPakeState::Round2Validated;
        Ok(())
    }

    /// BC 的 `CalculateKeyingMaterial`：K = (B / g^(x2·x4·s))^x2 mod p，寬度同 p。之後清除
    /// s、x2 與 B。K 要再經過 KDF 才能當作金鑰；確認雙方一致要靠第三輪。對 x2 與 s 是常數
    /// 時間。
    pub fn calculate_keying_material(&mut self) -> Result<Zeroizing<PaddedBigUint>, JPakeError> {
        let session = self.session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::KeyCalculated, JPakeState::Round2Validated)?;
        let key = session.domain.keying_material(
            required(&session.gx4)?,
            required(&session.x2)?,
            required(&session.s)?,
            required(&session.b)?,
        );
        session.s = None;
        session.x2 = None;
        session.b = None;
        session.state = JPakeState::KeyCalculated;
        Ok(key)
    }

    /// BC 的 `CreateRound3PayloadToSend`：以協商結果算出金鑰確認的 MacTag 寄給對方。
    /// 變動時間：K 的前導零位元組個數反映在時間上，見 BC 的 MacTag 編碼。
    pub fn create_round3_payload_to_send(
        &mut self,
        keying_material: &PaddedBigUint,
    ) -> Result<JPakeRound3Payload, JPakeError> {
        let Self {
            digest, session, ..
        } = self;
        let session = session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::Round3Created, JPakeState::KeyCalculated)?;
        let tag = mac_tag(
            &session.participant_id,
            required(&session.partner_participant_id)?,
            session.gx()?,
            keying_material,
            digest,
        );
        session.state = JPakeState::Round3Created;
        Ok(JPakeRound3Payload::new(&session.participant_id, tag))
    }

    /// BC 的 `ValidateRound3PayloadReceived`：酬載要來自第一輪的對象，MacTag 相符，比對
    /// 不會提早結束；成立後清除 g^x1 到 g^x4。變動時間：K 的前導零位元組個數反映在時間上，同
    /// [`create_round3_payload_to_send`](Self::create_round3_payload_to_send)；比對結果只由
    /// 錯誤透露。
    pub fn validate_round3_payload_received(
        &mut self,
        payload: &JPakeRound3Payload,
        keying_material: &PaddedBigUint,
    ) -> Result<(), JPakeError> {
        let Self {
            digest, session, ..
        } = self;
        let session = session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::Round3Validated, JPakeState::KeyCalculated)?;
        let partner = payload.participant_id();
        validate_participant_ids_differ(&session.participant_id, partner)?;
        validate_participant_ids_equal(required(&session.partner_participant_id)?, partner)?;
        validate_mac_tag(
            &session.participant_id,
            partner,
            session.gx()?,
            keying_material,
            digest,
            payload.mac_tag(),
        )?;
        session.gx1 = None;
        session.gx2 = None;
        session.gx3 = None;
        session.gx4 = None;
        session.state = JPakeState::Round3Validated;
        Ok(())
    }
}

impl Session {
    /// BC 每一步開頭的檢查：進度已到 `done` 表示這一步做過，未到 `needed` 表示前一步還沒
    /// 完成。常數時間。
    fn check(&self, done: JPakeState, needed: JPakeState) -> Result<(), JPakeError> {
        if self.state >= done {
            Err(JPakeError::RepeatedStep)
        } else if self.state < needed {
            Err(JPakeError::PrematureStep)
        } else {
            Ok(())
        }
    }

    /// g^x1 到 g^x4；跳過第一輪的建立或驗證時缺少。常數時間。
    fn gx(&self) -> Result<[&PaddedBigUint; 4], JPakeError> {
        Ok([
            required(&self.gx1)?,
            required(&self.gx2)?,
            required(&self.gx3)?,
            required(&self.gx4)?,
        ])
    }
}

/// 前面的步驟留下的值；跳過了那一步時回傳 [`JPakeError::PrematureStep`]。常數時間。
fn required<T>(value: &Option<T>) -> Result<&T, JPakeError> {
    value.as_ref().ok_or(JPakeError::PrematureStep)
}
