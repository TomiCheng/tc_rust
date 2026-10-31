use alloc::string::String;
use alloc::vec::Vec;
use tc_bigint::PaddedBigUint;

/// Schnorr 零知識證明 {g^v, r = v − x·h mod q}，證明知道 g^x 的 x；BC 以兩個元素的陣列
/// 表示。只是容器，收到時才驗證。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JPakeZeroKnowledgeProof {
    gv: PaddedBigUint,
    r: PaddedBigUint,
}

impl JPakeZeroKnowledgeProof {
    /// 包起 g^v 與 r，不檢查。常數時間。
    pub fn new(gv: PaddedBigUint, r: PaddedBigUint) -> Self {
        Self { gv, r }
    }

    /// g^v。常數時間。
    pub fn gv(&self) -> &PaddedBigUint {
        &self.gv
    }

    /// r = v − x·h mod q。常數時間。
    pub fn r(&self) -> &PaddedBigUint {
        &self.r
    }
}

/// BC 的 `JPakeRound1Payload`：第一輪寄給對方的 g^x1、g^x2 與兩者的零知識證明。只是
/// 容器，由 `JPakeParticipant::validate_round1_payload_received` 驗證。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JPakeRound1Payload {
    participant_id: String,
    gx1: PaddedBigUint,
    gx2: PaddedBigUint,
    knowledge_proof_for_x1: JPakeZeroKnowledgeProof,
    knowledge_proof_for_x2: JPakeZeroKnowledgeProof,
}

impl JPakeRound1Payload {
    /// 包起各欄位，不檢查。常數時間。
    pub fn new(
        participant_id: &str,
        gx1: PaddedBigUint,
        gx2: PaddedBigUint,
        knowledge_proof_for_x1: JPakeZeroKnowledgeProof,
        knowledge_proof_for_x2: JPakeZeroKnowledgeProof,
    ) -> Self {
        Self {
            participant_id: participant_id.into(),
            gx1,
            gx2,
            knowledge_proof_for_x1,
            knowledge_proof_for_x2,
        }
    }

    /// 寄件者的參與者 ID。常數時間。
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    /// g^x1。常數時間。
    pub fn gx1(&self) -> &PaddedBigUint {
        &self.gx1
    }

    /// g^x2。常數時間。
    pub fn gx2(&self) -> &PaddedBigUint {
        &self.gx2
    }

    /// x1 的零知識證明。常數時間。
    pub fn knowledge_proof_for_x1(&self) -> &JPakeZeroKnowledgeProof {
        &self.knowledge_proof_for_x1
    }

    /// x2 的零知識證明。常數時間。
    pub fn knowledge_proof_for_x2(&self) -> &JPakeZeroKnowledgeProof {
        &self.knowledge_proof_for_x2
    }
}

/// BC 的 `JPakeRound2Payload`：第二輪寄給對方的 A = g^((x1 + x3 + x4)·x2·s) 與 x2·s 的零
/// 知識證明。只是容器，由 `JPakeParticipant::validate_round2_payload_received` 驗證。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JPakeRound2Payload {
    participant_id: String,
    a: PaddedBigUint,
    knowledge_proof_for_x2s: JPakeZeroKnowledgeProof,
}

impl JPakeRound2Payload {
    /// 包起各欄位，不檢查。常數時間。
    pub fn new(
        participant_id: &str,
        a: PaddedBigUint,
        knowledge_proof_for_x2s: JPakeZeroKnowledgeProof,
    ) -> Self {
        Self {
            participant_id: participant_id.into(),
            a,
            knowledge_proof_for_x2s,
        }
    }

    /// 寄件者的參與者 ID。常數時間。
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    /// A。常數時間。
    pub fn a(&self) -> &PaddedBigUint {
        &self.a
    }

    /// x2·s 的零知識證明。常數時間。
    pub fn knowledge_proof_for_x2s(&self) -> &JPakeZeroKnowledgeProof {
        &self.knowledge_proof_for_x2s
    }
}

/// BC 的 `JPakeRound3Payload`：第三輪寄給對方的金鑰確認 MacTag。BC 把 MacTag 轉成有號
/// 整數，這裡保留 MAC 輸出的位元組。只是容器，由
/// `JPakeParticipant::validate_round3_payload_received` 驗證。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JPakeRound3Payload {
    participant_id: String,
    mac_tag: Vec<u8>,
}

impl JPakeRound3Payload {
    /// 包起各欄位，不檢查。常數時間。
    pub fn new(participant_id: &str, mac_tag: Vec<u8>) -> Self {
        Self {
            participant_id: participant_id.into(),
            mac_tag,
        }
    }

    /// 寄件者的參與者 ID。常數時間。
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    /// MacTag。常數時間。
    pub fn mac_tag(&self) -> &[u8] {
        &self.mac_tag
    }
}
