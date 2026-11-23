use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::{PolicyTree, TrustAnchor};

// BC 的 PkixCertPathValidatorResult；公鑰以 SPKI 回傳，DSA 繼承的參數已經補上
#[derive(Clone, Debug)]
pub struct PkixCertPathValidatorResult {
    trust_anchor: TrustAnchor,
    policy_tree: Option<PolicyTree>,
    subject_public_key: SubjectPublicKeyInfo,
}

impl PkixCertPathValidatorResult {
    pub(crate) fn new(
        trust_anchor: TrustAnchor,
        policy_tree: Option<PolicyTree>,
        subject_public_key: SubjectPublicKeyInfo,
    ) -> Self {
        Self {
            trust_anchor,
            policy_tree,
            subject_public_key,
        }
    }

    pub fn trust_anchor(&self) -> &TrustAnchor {
        &self.trust_anchor
    }

    pub fn policy_tree(&self) -> Option<&PolicyTree> {
        self.policy_tree.as_ref()
    }

    pub fn subject_public_key(&self) -> &SubjectPublicKeyInfo {
        &self.subject_public_key
    }
}
