use std::sync::Arc;

use tc_x509::X509Operator;
use tc_x509::cert::X509Certificate;

use crate::util::{find_trust_anchor, is_self_issued};
use crate::validator::PkixCertPathValidator;
use crate::{PkixBuilderParameters, PkixCertPath, PkixCertPathValidatorResult, PkixError};

const MAX_NODES: usize = 262_144;

type Source = Box<dyn std::error::Error + Send + Sync>;

// BC 的 PkixCertPathBuilderResult：建出的路徑加上驗證結果
#[derive(Clone, Debug)]
pub struct PkixCertPathBuilderResult {
    cert_path: PkixCertPath,
    result: PkixCertPathValidatorResult,
}

impl PkixCertPathBuilderResult {
    pub fn cert_path(&self) -> &PkixCertPath {
        &self.cert_path
    }

    pub fn validator_result(&self) -> &PkixCertPathValidatorResult {
        &self.result
    }
}

// BC 的 PkixCertPathBuilder：從目標憑證往上，在 store 裡以主體名稱找簽發者，深度優先，接到信任錨就驗證
pub struct PkixCertPathBuilder {
    x509: Arc<dyn X509Operator>,
    for_crl_check: bool,
}

struct Search {
    last: Option<(String, Option<Source>)>,
    nodes: usize,
}

enum Stop {
    Budget,
}

impl PkixCertPathBuilder {
    pub fn new(x509: Arc<dyn X509Operator>) -> Self {
        Self {
            x509,
            for_crl_check: false,
        }
    }

    pub(crate) fn for_crl_check(x509: Arc<dyn X509Operator>) -> Self {
        Self {
            x509,
            for_crl_check: true,
        }
    }

    pub fn build(
        &self,
        params: &PkixBuilderParameters,
    ) -> Result<PkixCertPathBuilderResult, PkixError> {
        let mut search = Search {
            last: None,
            nodes: 0,
        };
        for target in targets(params)? {
            let mut path = Vec::new();
            match self.build_from(&target, params, &mut path, &mut search) {
                Ok(Some(result)) => return Ok(result),
                Ok(None) => {}
                Err(Stop::Budget) => {
                    return Err(PkixError::Builder(
                        "certification path build exceeded node limit".into(),
                        None,
                    ));
                }
            }
        }
        Err(match search.last {
            None => PkixError::Builder("Unable to find certificate chain.".into(), None),
            Some((message, source)) => PkixError::Builder(message, source),
        })
    }

    fn build_from(
        &self,
        cert: &X509Certificate,
        params: &PkixBuilderParameters,
        path: &mut Vec<X509Certificate>,
        search: &mut Search,
    ) -> Result<Option<PkixCertPathBuilderResult>, Stop> {
        search.nodes += 1;
        if search.nodes > MAX_NODES {
            return Err(Stop::Budget);
        }
        if path.contains(cert) || params.excluded_certificates().contains(cert) {
            return Ok(None);
        }
        if let Some(max) = params.max_path_length() {
            if count_intermediates(path, cert) > max {
                return Ok(None);
            }
        }
        path.push(cert.clone());
        let outcome = self.step(cert, params, path, search);
        path.pop();
        match outcome {
            Ok(found) => Ok(found),
            Err(Failure::Stop(stop)) => Err(stop),
            Err(Failure::Error(message, source)) => {
                search.last = Some((message, source));
                Ok(None)
            }
        }
    }

    fn step(
        &self,
        cert: &X509Certificate,
        params: &PkixBuilderParameters,
        path: &mut Vec<X509Certificate>,
        search: &mut Search,
    ) -> Result<Option<PkixCertPathBuilderResult>, Failure> {
        let anchors = params.params().trust_anchors();
        let issuer_is_anchor = matches!(find_trust_anchor(&*self.x509, cert, anchors), Ok(Some(_)));
        if issuer_is_anchor {
            let validator = if self.for_crl_check {
                PkixCertPathValidator::for_crl_check(self.x509.clone())
            } else {
                PkixCertPathValidator::new(self.x509.clone())
            };
            let cert_path = PkixCertPath::new(path.clone());
            let result = validator
                .validate(&cert_path, params.params())
                .map_err(|e| {
                    Failure::Error(
                        "Certification path could not be validated.".into(),
                        Some(e.into()),
                    )
                })?;
            return Ok(Some(PkixCertPathBuilderResult { cert_path, result }));
        }
        let issuers: Vec<&X509Certificate> = params
            .params()
            .certificate_stores()
            .iter()
            .flat_map(|store| store.certificates())
            .filter(|candidate| candidate.subject().equivalent(cert.issuer()))
            .collect();
        if issuers.is_empty() {
            return Err(Failure::Error(
                "No issuer certificate for certificate in certification path found.".into(),
                None,
            ));
        }
        let mut seen: Vec<&X509Certificate> = Vec::new();
        for issuer in issuers {
            if seen.contains(&issuer) {
                continue;
            }
            seen.push(issuer);
            if let Some(result) = self
                .build_from(issuer, params, path, search)
                .map_err(Failure::Stop)?
            {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }
}

enum Failure {
    Stop(Stop),
    Error(String, Option<Source>),
}

// BC 的 FindTargets：指定的那張憑證，或 store 裡符合 targetConstraints 的憑證
fn targets(params: &PkixBuilderParameters) -> Result<Vec<X509Certificate>, PkixError> {
    let inner = params.params();
    if let Some(target) = inner.target_certificate() {
        return Ok(vec![target.clone()]);
    }
    let mut found: Vec<X509Certificate> = Vec::new();
    if let Some(selector) = inner.target_constraints() {
        for certificate in inner
            .certificate_stores()
            .iter()
            .flat_map(|s| s.certificates())
        {
            if selector.matches(certificate) && !found.contains(certificate) {
                found.push(certificate.clone());
            }
        }
    }
    if found.is_empty() {
        return Err(PkixError::Builder(
            "No certificate found matching targetConstraints.".into(),
            None,
        ));
    }
    Ok(found)
}

// BC 的 CountIntermediates
fn count_intermediates(path: &[X509Certificate], cert: &X509Certificate) -> usize {
    if path.is_empty() {
        return 0;
    }
    let intermediates = path[1..].iter().filter(|c| !is_self_issued(c)).count();
    intermediates + usize::from(!is_self_issued(cert))
}
