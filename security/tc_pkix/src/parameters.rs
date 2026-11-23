use std::collections::BTreeSet;
use std::sync::Arc;

use tc_asn1::Asn1Oid;
use tc_asn1_x509::cert::Time;
use tc_x509::cert::X509Certificate;
use tc_x509::store::{X509CertSelector, X509CertificateStore, X509CrlStore};

use crate::{CertPathChecker, TrustAnchor};

// BC 的 PkixValidityModel／ChainValidityModel
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum ValidityModel {
    // 每張憑證在驗證時間都必須有效
    #[default]
    Pkix,
    // 每張憑證在下一張憑證簽發時有效即可
    Chain,
}

// BC 的 PkixParameters；預設同 BC：檢查撤銷、拒絕關鍵的政策限定詞
#[derive(Clone)]
pub struct PkixParameters {
    trust_anchors: Vec<TrustAnchor>,
    date: Option<Time>,
    checkers: Vec<Arc<dyn CertPathChecker>>,
    revocation_enabled: bool,
    initial_policies: BTreeSet<Asn1Oid>,
    explicit_policy_required: bool,
    any_policy_inhibited: bool,
    policy_mapping_inhibited: bool,
    policy_qualifiers_rejected: bool,
    certificate_stores: Vec<X509CertificateStore>,
    crl_stores: Vec<X509CrlStore>,
    target_constraints: Option<X509CertSelector>,
    target_certificate: Option<X509Certificate>,
    validity_model: ValidityModel,
    use_deltas: bool,
}

impl PkixParameters {
    pub fn new(trust_anchors: Vec<TrustAnchor>) -> Self {
        Self {
            trust_anchors,
            date: None,
            checkers: Vec::new(),
            revocation_enabled: true,
            initial_policies: BTreeSet::new(),
            explicit_policy_required: false,
            any_policy_inhibited: false,
            policy_mapping_inhibited: false,
            policy_qualifiers_rejected: true,
            certificate_stores: Vec::new(),
            crl_stores: Vec::new(),
            target_constraints: None,
            target_certificate: None,
            validity_model: ValidityModel::Pkix,
            use_deltas: false,
        }
    }

    pub fn with_trust_anchors(mut self, trust_anchors: Vec<TrustAnchor>) -> Self {
        self.trust_anchors = trust_anchors;
        self
    }

    // 驗證時間；None 用現在
    pub fn with_date(mut self, date: Option<Time>) -> Self {
        self.date = date;
        self
    }

    pub fn with_checker(mut self, checker: Arc<dyn CertPathChecker>) -> Self {
        self.checkers.push(checker);
        self
    }

    pub fn with_revocation_enabled(mut self, enabled: bool) -> Self {
        self.revocation_enabled = enabled;
        self
    }

    // user-initial-policy-set；空集合表示 any-policy
    pub fn with_initial_policies(mut self, policies: BTreeSet<Asn1Oid>) -> Self {
        self.initial_policies = policies;
        self
    }

    pub fn with_explicit_policy_required(mut self, required: bool) -> Self {
        self.explicit_policy_required = required;
        self
    }

    pub fn with_any_policy_inhibited(mut self, inhibited: bool) -> Self {
        self.any_policy_inhibited = inhibited;
        self
    }

    pub fn with_policy_mapping_inhibited(mut self, inhibited: bool) -> Self {
        self.policy_mapping_inhibited = inhibited;
        self
    }

    pub fn with_policy_qualifiers_rejected(mut self, rejected: bool) -> Self {
        self.policy_qualifiers_rejected = rejected;
        self
    }

    pub fn with_certificate_store(mut self, store: X509CertificateStore) -> Self {
        self.certificate_stores.push(store);
        self
    }

    pub fn with_crl_store(mut self, store: X509CrlStore) -> Self {
        self.crl_stores.push(store);
        self
    }

    pub fn with_target_constraints(mut self, selector: Option<X509CertSelector>) -> Self {
        self.target_constraints = selector;
        self
    }

    // BC 以 X509CertStoreSelector.Certificate 指定的那一張目標憑證
    pub fn with_target_certificate(mut self, certificate: Option<X509Certificate>) -> Self {
        self.target_certificate = certificate;
        self
    }

    pub fn with_validity_model(mut self, model: ValidityModel) -> Self {
        self.validity_model = model;
        self
    }

    pub fn with_use_deltas(mut self, use_deltas: bool) -> Self {
        self.use_deltas = use_deltas;
        self
    }

    pub fn trust_anchors(&self) -> &[TrustAnchor] {
        &self.trust_anchors
    }

    pub fn date(&self) -> Option<Time> {
        self.date
    }

    pub fn checkers(&self) -> &[Arc<dyn CertPathChecker>] {
        &self.checkers
    }

    pub fn is_revocation_enabled(&self) -> bool {
        self.revocation_enabled
    }

    pub fn initial_policies(&self) -> &BTreeSet<Asn1Oid> {
        &self.initial_policies
    }

    pub fn is_explicit_policy_required(&self) -> bool {
        self.explicit_policy_required
    }

    pub fn is_any_policy_inhibited(&self) -> bool {
        self.any_policy_inhibited
    }

    pub fn is_policy_mapping_inhibited(&self) -> bool {
        self.policy_mapping_inhibited
    }

    pub fn is_policy_qualifiers_rejected(&self) -> bool {
        self.policy_qualifiers_rejected
    }

    pub fn certificate_stores(&self) -> &[X509CertificateStore] {
        &self.certificate_stores
    }

    pub fn crl_stores(&self) -> &[X509CrlStore] {
        &self.crl_stores
    }

    pub fn target_constraints(&self) -> Option<&X509CertSelector> {
        self.target_constraints.as_ref()
    }

    pub fn target_certificate(&self) -> Option<&X509Certificate> {
        self.target_certificate.as_ref()
    }

    pub fn validity_model(&self) -> ValidityModel {
        self.validity_model
    }

    pub fn is_use_deltas_enabled(&self) -> bool {
        self.use_deltas
    }

    // BC 的 SetTrustAnchor：驗證時只留下找到的那個信任錨，CRL 也只能出自它
    pub(crate) fn restricted_to(&self, anchor: &TrustAnchor) -> Self {
        let mut params = self.clone();
        params.trust_anchors = vec![anchor.clone()];
        params
    }
}

// BC 的 PkixBuilderParameters：路徑最多幾張中繼憑證（None 是不限，對應 BC 的 -1），以及不採用的憑證
#[derive(Clone)]
pub struct PkixBuilderParameters {
    params: PkixParameters,
    max_path_length: Option<usize>,
    excluded_certificates: Vec<X509Certificate>,
}

impl PkixBuilderParameters {
    pub fn new(params: PkixParameters) -> Self {
        Self {
            params,
            max_path_length: Some(5),
            excluded_certificates: Vec::new(),
        }
    }

    pub fn with_max_path_length(mut self, length: Option<usize>) -> Self {
        self.max_path_length = length;
        self
    }

    pub fn with_excluded_certificates(mut self, certificates: Vec<X509Certificate>) -> Self {
        self.excluded_certificates = certificates;
        self
    }

    pub fn params(&self) -> &PkixParameters {
        &self.params
    }

    pub fn max_path_length(&self) -> Option<usize> {
        self.max_path_length
    }

    pub fn excluded_certificates(&self) -> &[X509Certificate] {
        &self.excluded_certificates
    }
}
