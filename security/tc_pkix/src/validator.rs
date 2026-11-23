use std::collections::BTreeSet;
use std::sync::Arc;

use tc_asn1::{Asn1Integer, Asn1Object, Asn1Oid, Decode, DecodingOptions};
use tc_asn1_x500::{AttributeType, AttributeValue, Name};
use tc_asn1_x509::cert::{SubjectPublicKeyInfo, Time, Version};
use tc_asn1_x509::ext::{
    BasicConstraints, CertificatePolicies, ExtensionId, InhibitAnyPolicy, KeyUsage,
    NameConstraints, PolicyConstraints, PolicyQualifierInfo,
};
use tc_asn1_x509::name::GeneralNames;
use tc_x509::X509Operator;
use tc_x509::cert::X509Certificate;

use crate::crl::check_crls;
use crate::name_constraints::NameConstraintValidator;
use crate::policy_node::NodeData;
use crate::util::{
    any_policy, certificate_extension, critical_extension_oids, decode_error, error,
    find_trust_anchor, has_critical_extension, is_self_issued, next_working_key, now, oid,
    verify_certificate,
};
use crate::{
    CertPathChecker, CertPathValidatorError, PkixCertPath, PkixCertPathValidatorResult, PkixError,
    PkixParameters, PolicyTree, ValidatorReason, ValidityModel,
};

const MAX_POLICY_NODES: usize = 8192;
const ID_RSP_ROLE_EUICC: &str = "2.23.146.1.2.1.1";
const ID_RSP_ROLE_EUM: &str = "2.23.146.1.2.1.2";
const ID_ISIS_MTT_AT_DATE_OF_CERT_GEN: &str = "1.3.36.8.3.1";

type Result<T> = std::result::Result<T, CertPathValidatorError>;

// BC 的 PkixCertPathValidator：RFC 5280 第 6 章的路徑驗證；驗章與公鑰解碼交給 X509Operator
pub struct PkixCertPathValidator {
    x509: Arc<dyn X509Operator>,
    for_crl_check: bool,
}

impl PkixCertPathValidator {
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

    pub fn validate(
        &self,
        path: &PkixCertPath,
        params: &PkixParameters,
    ) -> std::result::Result<PkixCertPathValidatorResult, PkixError> {
        if params.trust_anchors().is_empty() {
            return Err(PkixError::InvalidParameters(
                "trustAnchors is empty, this is not allowed for certification path validation.",
            ));
        }
        Ok(self.run(path, params)?)
    }

    fn run(
        &self,
        path: &PkixCertPath,
        params: &PkixParameters,
    ) -> Result<PkixCertPathValidatorResult> {
        let x509 = &*self.x509;
        let certs = path.certificates();
        let n = certs.len();
        if n == 0 {
            return Err(error(
                "Certification path is empty.",
                Some(0),
                ValidatorReason::Unspecified,
            ));
        }
        let current_date = now();
        let validity_date = params.date().unwrap_or(current_date);

        let anchors = params.trust_anchors();
        let trust = match find_trust_anchor(x509, &certs[n - 1], anchors) {
            Ok(Some(trust)) => trust.clone(),
            Ok(None) => {
                return Err(error(
                    "Trust anchor for certification path not found.",
                    None,
                    ValidatorReason::NoTrustAnchor,
                ));
            }
            Err(failure) => {
                return Err(error(
                    "TrustAnchor found but certificate validation failed.",
                    Some(n - 1),
                    ValidatorReason::InvalidSignature,
                )
                .with_source(failure));
            }
        };
        // RFC 5280：CRL 必須出自同一個信任錨
        let restricted;
        let params = if anchors.len() > 1 {
            restricted = params.restricted_to(&trust);
            &restricted
        } else {
            params
        };
        for checker in params.checkers() {
            checker
                .init(false)
                .map_err(|e| error(e.to_string(), None, ValidatorReason::Unspecified))?;
        }

        // 6.1.2
        let mut policy = PolicyState::new(n);
        let mut name_constraints = NameConstraintValidator::new();
        let mut acceptable_policies = BTreeSet::new();
        let mut explicit_policy = if params.is_explicit_policy_required() {
            0
        } else {
            n + 1
        };
        let mut inhibit_any_policy = if params.is_any_policy_inhibited() {
            0
        } else {
            n + 1
        };
        let mut policy_mapping = if params.is_policy_mapping_inhibited() {
            0
        } else {
            n + 1
        };
        let mut sign = trust.trusted_certificate().cloned();
        let mut working_issuer_name = trust.subject().clone();
        let mut working_public_key = trust.subject_public_key_info().clone();
        let mut max_path_length = n;

        // 6.1.3
        if params
            .target_certificate()
            .is_some_and(|target| *target != certs[0])
        {
            return Err(error(
                "Target certificate in certification path does not match targetConstraints.",
                Some(0),
                ValidatorReason::Unspecified,
            ));
        }
        if let Some(target) = params.target_constraints() {
            if !target.matches(&certs[0]) {
                return Err(error(
                    "Target certificate in certification path does not match targetConstraints.",
                    Some(0),
                    ValidatorReason::Unspecified,
                ));
            }
        }

        let mut index = n;
        while index > 0 {
            index -= 1;
            let i = n - index;
            let cert = &certs[index];
            let verification_already_performed = index == n - 1;

            self.process_cert_a(
                path,
                params,
                current_date,
                validity_date,
                index,
                &working_public_key,
                verification_already_performed,
                &working_issuer_name,
                sign.as_ref(),
            )?;
            process_cert_bc(path, index, &mut name_constraints, self.for_crl_check)?;
            process_cert_d(
                path,
                index,
                &mut acceptable_policies,
                &mut policy,
                inhibit_any_policy,
                self.for_crl_check,
            )?;
            process_cert_e(path, index, &mut policy)?;
            if explicit_policy == 0 && !policy.valid {
                return Err(error(
                    "No valid policy tree found when one expected.",
                    Some(index),
                    ValidatorReason::InvalidPolicy,
                ));
            }

            // 6.1.4
            if i != n {
                if cert.version() == Version::V1 {
                    if i == 1 && trust.trusted_certificate() == Some(cert) {
                        continue;
                    }
                    return Err(error(
                        "Version 1 certificates can't be used as CA ones.",
                        Some(index),
                        ValidatorReason::NotCaCertificate,
                    ));
                }
                prepare_next_cert_a(cert, index)?;
                prepare_cert_b(path, index, &mut policy, policy_mapping)?;
                prepare_next_cert_g(cert, index, &mut name_constraints)?;

                // (h)
                if !is_self_issued(cert) {
                    explicit_policy = explicit_policy.saturating_sub(1);
                    policy_mapping = policy_mapping.saturating_sub(1);
                    inhibit_any_policy = inhibit_any_policy.saturating_sub(1);
                }
                // (i)
                let constraints = policy_constraints(cert, index)?;
                if let Some(pc) = &constraints {
                    if let Some(require) = pc.require_explicit_policy() {
                        let value = to_usize(require, index)?;
                        explicit_policy = explicit_policy.min(value);
                    }
                    if let Some(inhibit) = pc.inhibit_policy_mapping() {
                        let value = to_usize(inhibit, index)?;
                        policy_mapping = policy_mapping.min(value);
                    }
                }
                // (j)
                let iap: Option<InhibitAnyPolicy> =
                    certificate_extension(cert, &ExtensionId::INHIBIT_ANY_POLICY.oid()).map_err(
                        |e| {
                            decode_error(
                                "Inhibit any-policy extension cannot be decoded.",
                                Some(index),
                                e,
                            )
                        },
                    )?;
                if let Some(iap) = iap {
                    inhibit_any_policy = inhibit_any_policy.min(to_usize(iap.skip_certs(), index)?);
                }
                // (k)
                let basic_constraints = prepare_next_cert_k(cert, index)?;
                // (l)
                if !is_self_issued(cert) {
                    if max_path_length == 0 {
                        return Err(error(
                            "Max path length not greater than zero",
                            Some(index),
                            ValidatorReason::PathTooLong,
                        ));
                    }
                    max_path_length -= 1;
                }
                // (m)
                if let Some(length) = basic_constraints.path_len_constraint() {
                    if let Ok(length) = usize::try_from(length) {
                        max_path_length = max_path_length.min(length);
                    }
                }
                // (n)
                prepare_next_cert_n(cert, index)?;

                // (o)
                let mut critical = critical_extension_oids(cert.extensions());
                for handled in HANDLED_BY_ALGORITHM {
                    critical.remove(&handled.oid());
                }
                run_checkers(params.checkers(), cert, &mut critical, index, None)?;

                sign = Some(cert.clone());
                working_issuer_name = cert.subject().clone();
                working_public_key = next_working_key(certs, index).map_err(|e| {
                    error(
                        "Next working key could not be retrieved.",
                        Some(index),
                        e.reason(),
                    )
                    .with_source(e)
                })?;
            }
        }

        // 6.1.5
        let cert = &certs[index];
        if !is_self_issued(cert) {
            explicit_policy = explicit_policy.saturating_sub(1);
        }
        if let Some(pc) = policy_constraints(cert, index)? {
            if let Some(require) = pc.require_explicit_policy() {
                if to_usize(require, index)? == 0 {
                    explicit_policy = 0;
                }
            }
        }
        let mut critical = critical_extension_oids(cert.extensions());
        for handled in HANDLED_BY_ALGORITHM.iter().chain(&HANDLED_AT_WRAP_UP) {
            critical.remove(&handled.oid());
        }
        run_checkers(
            params.checkers(),
            cert,
            &mut critical,
            index,
            Some("Additional certificate path checker failed."),
        )?;
        let intersection = wrapup_cert_g(params, n, index, &mut policy, &acceptable_policies)?;

        if explicit_policy > 0 || intersection.is_some() {
            return Ok(PkixCertPathValidatorResult::new(
                trust,
                intersection,
                cert.subject_public_key_info().clone(),
            ));
        }
        // BC 在迴圈之後回報，位置是 -1
        Err(error(
            "Path processing failed on policy.",
            None,
            ValidatorReason::InvalidPolicy,
        ))
    }

    // BC 的 ProcessCertA：(1) 簽章 (2) 有效期間 (3) 撤銷 (4) 名稱串接
    #[allow(clippy::too_many_arguments)]
    fn process_cert_a(
        &self,
        path: &PkixCertPath,
        params: &PkixParameters,
        current_date: Time,
        validity_date: Time,
        index: usize,
        working_public_key: &SubjectPublicKeyInfo,
        verification_already_performed: bool,
        working_issuer_name: &Name,
        sign: Option<&X509Certificate>,
    ) -> Result<()> {
        let certs = path.certificates();
        let cert = &certs[index];
        if !verification_already_performed {
            verify_certificate(&*self.x509, cert, working_public_key).map_err(|e| {
                error(
                    "Could not validate certificate signature.",
                    Some(index),
                    ValidatorReason::InvalidSignature,
                )
                .with_source(e)
            })?;
        }
        let validity_date = valid_cert_date(validity_date, params.validity_model(), path, index)?;
        if validity_date > cert.not_after() {
            return Err(error(
                format!(
                    "Could not validate certificate: certificate expired on {}",
                    validity_text(cert.not_after())
                ),
                Some(index),
                ValidatorReason::Expired,
            ));
        }
        if validity_date < cert.not_before() {
            return Err(error(
                format!(
                    "Could not validate certificate: certificate not valid until {}",
                    validity_text(cert.not_before())
                ),
                Some(index),
                ValidatorReason::NotYetValid,
            ));
        }
        if params.is_revocation_enabled() {
            check_crls(
                &self.x509,
                index,
                params,
                cert,
                current_date,
                validity_date,
                sign,
                working_public_key,
                certs,
            )?;
        }
        if !cert.issuer().equivalent(working_issuer_name) {
            return Err(error(
                format!(
                    "IssuerName({}) does not match SubjectName({}) of signing certificate.",
                    cert.issuer(),
                    working_issuer_name
                ),
                Some(index),
                ValidatorReason::NameChaining,
            ));
        }
        Ok(())
    }
}

// 演算法自己處理的關鍵擴充，(o) 與 wrap-up 都不交給 checker
const HANDLED_BY_ALGORITHM: [tc_asn1::NamedOid; 10] = [
    ExtensionId::KEY_USAGE,
    ExtensionId::CERTIFICATE_POLICIES,
    ExtensionId::POLICY_MAPPINGS,
    ExtensionId::INHIBIT_ANY_POLICY,
    ExtensionId::ISSUING_DISTRIBUTION_POINT,
    ExtensionId::DELTA_CRL_INDICATOR,
    ExtensionId::POLICY_CONSTRAINTS,
    ExtensionId::BASIC_CONSTRAINTS,
    ExtensionId::SUBJECT_ALT_NAME,
    ExtensionId::NAME_CONSTRAINTS,
];

// 終端憑證另外允許的
const HANDLED_AT_WRAP_UP: [tc_asn1::NamedOid; 2] = [
    ExtensionId::CRL_DISTRIBUTION_POINTS,
    ExtensionId::EXT_KEY_USAGE,
];

// BC 的 yyyyMMddHHmmssK
fn validity_text(time: Time) -> String {
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

fn to_usize(value: &Asn1Integer, index: usize) -> Result<usize> {
    u64::try_from(value)
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            error(
                "Policy constraints extension contents cannot be decoded.",
                Some(index),
                ValidatorReason::Unspecified,
            )
        })
}

fn policy_constraints(cert: &X509Certificate, index: usize) -> Result<Option<PolicyConstraints>> {
    certificate_extension(cert, &ExtensionId::POLICY_CONSTRAINTS.oid()).map_err(|e| {
        decode_error(
            "Policy constraints extension cannot be decoded.",
            Some(index),
            e,
        )
    })
}

fn certificate_policies(
    cert: &X509Certificate,
    index: usize,
) -> Result<Option<CertificatePolicies>> {
    certificate_extension(cert, &ExtensionId::CERTIFICATE_POLICIES.oid()).map_err(|e| {
        decode_error(
            "Could not read certificate policies extension from certificate.",
            Some(index),
            e,
        )
    })
}

fn run_checkers(
    checkers: &[Arc<dyn CertPathChecker>],
    cert: &X509Certificate,
    critical: &mut BTreeSet<Asn1Oid>,
    index: usize,
    message: Option<&str>,
) -> Result<()> {
    for checker in checkers {
        checker.check(cert, critical).map_err(|e| {
            let reason = match &e {
                PkixError::Validator(inner) => inner.reason(),
                _ => ValidatorReason::Unspecified,
            };
            let text = message.map(str::to_owned).unwrap_or_else(|| e.to_string());
            error(text, Some(index), reason).with_source(e)
        })?;
    }
    if !critical.is_empty() {
        let list: Vec<String> = critical.iter().map(ToString::to_string).collect();
        return Err(error(
            format!(
                "Certificate has unsupported critical extension: [{}]",
                list.join(", ")
            ),
            Some(index),
            ValidatorReason::UnrecognizedCriticalExtension,
        ));
    }
    Ok(())
}

// BC 的 GetValidCertDateFromValidityModel
fn valid_cert_date(
    validity_date: Time,
    model: ValidityModel,
    path: &PkixCertPath,
    index: usize,
) -> Result<Time> {
    if model != ValidityModel::Chain || index == 0 {
        return Ok(validity_date);
    }
    let issued = &path.certificates()[index - 1];
    if index - 1 == 0 {
        let date: Option<tc_asn1::Asn1GeneralizedTime> =
            certificate_extension(issued, &oid(ID_ISIS_MTT_AT_DATE_OF_CERT_GEN)).map_err(|e| {
                decode_error(
                    "Date of cert gen extension could not be read.",
                    Some(index),
                    e,
                )
            })?;
        if let Some(date) = date {
            return Ok(Time::from(date));
        }
    }
    Ok(issued.not_before())
}

fn has_certificate_policy(cert: &X509Certificate, policy: &Asn1Oid) -> bool {
    matches!(
        certificate_extension::<CertificatePolicies>(cert, &ExtensionId::CERTIFICATE_POLICIES.oid()),
        Ok(Some(policies)) if policies.policies().iter().any(|p| p.policy_identifier() == policy)
    )
}

// BC 的 ProcessCertBC：名稱限制的允許與排除子樹；自簽發的中繼憑證不檢查
fn process_cert_bc(
    path: &PkixCertPath,
    index: usize,
    validator: &mut NameConstraintValidator,
    for_crl_check: bool,
) -> Result<()> {
    let certs = path.certificates();
    let cert = &certs[index];
    let n = certs.len();
    let i = n - index;
    if (i < n || for_crl_check) && is_self_issued(cert) {
        return Ok(());
    }
    let principal = cert.subject();
    // GSMA SGP.22：eUICC 憑證的主體比對 EUM 的名稱限制時放寬
    let sgp22 = certs.get(index + 1).is_some_and(|issuer| {
        has_certificate_policy(cert, &oid(ID_RSP_ROLE_EUICC))
            && has_certificate_policy(issuer, &oid(ID_RSP_ROLE_EUM))
    });
    let checked = if sgp22 {
        validator.check_dn_sgp22(principal)
    } else {
        validator.check_dn(principal)
    };
    checked.map_err(|e| {
        error(
            "Subtree check for certificate subject failed.",
            Some(index),
            ValidatorReason::InvalidName,
        )
        .with_source(e)
    })?;
    let alt_names: Option<GeneralNames> =
        certificate_extension(cert, &ExtensionId::SUBJECT_ALT_NAME.oid()).map_err(|e| {
            decode_error(
                "Subject alternative name extension could not be decoded.",
                Some(index),
                e,
            )
        })?;
    for email in email_addresses(principal) {
        validator.check_email(&email).map_err(|e| {
            error(
                "Subtree check for certificate subject alternative email failed.",
                Some(index),
                ValidatorReason::InvalidName,
            )
            .with_source(e)
        })?;
    }
    if let Some(alt_names) = alt_names {
        for name in alt_names.names() {
            validator.check_name(name).map_err(|e| {
                error(
                    "Subtree check for certificate subject alternative name failed.",
                    Some(index),
                    ValidatorReason::InvalidName,
                )
                .with_source(e)
            })?;
        }
    }
    Ok(())
}

// BC 的 ExtractEmailAddressesFromSubjectDN
pub(crate) fn email_addresses(name: &Name) -> Vec<String> {
    let email = AttributeType::EMAIL_ADDRESS.oid();
    name.rdns()
        .iter()
        .flat_map(|rdn| rdn.attributes())
        .filter(|attribute| *attribute.attribute_type() == email)
        .filter_map(|attribute| match attribute.value() {
            AttributeValue::Ia5String(text) => Some(text.as_str().to_owned()),
            AttributeValue::DirectoryString(text) => text.as_str().map(str::to_owned),
            _ => None,
        })
        .collect()
}

// BC 的 PrepareNextCertA：policyMappings 不能對應到或來自 anyPolicy
fn prepare_next_cert_a(cert: &X509Certificate, index: usize) -> Result<()> {
    let any = any_policy();
    for (issuer, subject) in policy_mappings(cert, index)?.iter().flatten() {
        if *issuer == any {
            return Err(error(
                "IssuerDomainPolicy is anyPolicy",
                Some(index),
                ValidatorReason::InvalidPolicy,
            ));
        }
        if *subject == any {
            return Err(error(
                "SubjectDomainPolicy is anyPolicy",
                Some(index),
                ValidatorReason::InvalidPolicy,
            ));
        }
    }
    Ok(())
}

// policyMappings 的 (issuerDomainPolicy, subjectDomainPolicy)。tc_asn1_x509 的 PolicyMappings 解碼時
// 就拒絕 anyPolicy，這裡要回報 BC 的 InvalidPolicy，所以自己讀
fn policy_mappings(
    cert: &X509Certificate,
    index: usize,
) -> Result<Option<Vec<(Asn1Oid, Asn1Oid)>>> {
    let Some(extension) = cert
        .extensions()
        .and_then(|e| e.get(ExtensionId::POLICY_MAPPINGS))
    else {
        return Ok(None);
    };
    let (_, object) = Asn1Object::decode(extension.extn_value(), &DecodingOptions::default())
        .map_err(|e| {
            decode_error(
                "Policy mappings extension could not be decoded.",
                Some(index),
                e,
            )
        })?;
    let contents = || {
        error(
            "Policy mappings extension contents could not be decoded.",
            Some(index),
            ValidatorReason::Unspecified,
        )
    };
    let Asn1Object::SequenceOf(mappings) = object else {
        return Err(contents());
    };
    let mut pairs = Vec::new();
    for mapping in mappings.elements() {
        match mapping {
            Asn1Object::SequenceOf(pair) => match pair.elements() {
                [Asn1Object::Oid(issuer), Asn1Object::Oid(subject)] => {
                    pairs.push((issuer.clone(), subject.clone()))
                }
                _ => return Err(contents()),
            },
            _ => return Err(contents()),
        }
    }
    Ok(Some(pairs))
}

fn prepare_next_cert_g(
    cert: &X509Certificate,
    index: usize,
    validator: &mut NameConstraintValidator,
) -> Result<()> {
    let constraints: Option<NameConstraints> =
        certificate_extension(cert, &ExtensionId::NAME_CONSTRAINTS.oid()).map_err(|e| {
            decode_error(
                "Name constraints extension could not be decoded.",
                Some(index),
                e,
            )
        })?;
    let Some(constraints) = constraints else {
        return Ok(());
    };
    if let Some(permitted) = constraints.permitted_subtrees() {
        validator
            .intersect_permitted_subtree(permitted.subtrees())
            .map_err(|e| {
                error(
                    "Permitted subtrees could not be built from name constraints extension.",
                    Some(index),
                    ValidatorReason::InvalidName,
                )
                .with_source(e)
            })?;
    }
    if let Some(excluded) = constraints.excluded_subtrees() {
        for subtree in excluded.subtrees() {
            validator.add_excluded_subtree(subtree).map_err(|e| {
                error(
                    "Excluded subtrees could not be built from name constraints extension.",
                    Some(index),
                    ValidatorReason::InvalidName,
                )
                .with_source(e)
            })?;
        }
    }
    Ok(())
}

fn prepare_next_cert_k(cert: &X509Certificate, index: usize) -> Result<BasicConstraints> {
    let constraints: Option<BasicConstraints> =
        certificate_extension(cert, &ExtensionId::BASIC_CONSTRAINTS.oid()).map_err(|e| {
            decode_error(
                "Basic constraints extension cannot be decoded.",
                Some(index),
                e,
            )
        })?;
    let Some(constraints) = constraints else {
        return Err(error(
            "Intermediate certificate lacks BasicConstraints",
            Some(index),
            ValidatorReason::NotCaCertificate,
        ));
    };
    if !constraints.is_ca() {
        return Err(error(
            "Not a CA certificate",
            Some(index),
            ValidatorReason::NotCaCertificate,
        ));
    }
    Ok(constraints)
}

fn prepare_next_cert_n(cert: &X509Certificate, index: usize) -> Result<()> {
    let usage: Option<KeyUsage> = certificate_extension(cert, &ExtensionId::KEY_USAGE.oid())
        .map_err(|e| decode_error("Key usage extension cannot be decoded.", Some(index), e))?;
    if usage.is_some_and(|usage| !usage.contains(KeyUsage::KEY_CERT_SIGN)) {
        return Err(error(
            "Issuer certificate keyusage extension is critical and does not permit key signing.",
            Some(index),
            ValidatorReason::InvalidKeyUsage,
        ));
    }
    Ok(())
}

// valid_policy_tree 與 BC 的 policyNodes：每一層還在樹上的節點；valid 為 false 對應 BC 的 null 樹
pub(crate) struct PolicyState {
    tree: PolicyTree,
    levels: Vec<Vec<usize>>,
    valid: bool,
}

impl PolicyState {
    fn new(n: usize) -> Self {
        let mut expected = BTreeSet::new();
        expected.insert(any_policy());
        let tree = PolicyTree::new(NodeData {
            depth: 0,
            valid_policy: any_policy(),
            expected_policies: expected,
            qualifiers: Vec::new(),
            critical: false,
            parent: None,
            children: Vec::new(),
        });
        let mut levels = vec![Vec::new(); n + 1];
        levels[0].push(0);
        Self {
            tree,
            levels,
            valid: true,
        }
    }

    fn add(
        &mut self,
        parent: usize,
        depth: usize,
        policy: Asn1Oid,
        expected: BTreeSet<Asn1Oid>,
        qualifiers: Vec<PolicyQualifierInfo>,
        critical: bool,
    ) {
        let child = self.tree.add_child(
            parent,
            NodeData {
                depth,
                valid_policy: policy,
                expected_policies: expected,
                qualifiers,
                critical,
                parent: None,
                children: Vec::new(),
            },
        );
        self.levels[depth].push(child);
    }

    fn find(&self, depth: usize, policy: &Asn1Oid) -> Option<usize> {
        self.levels[depth]
            .iter()
            .copied()
            .find(|&node| self.tree.node(node).valid_policy == *policy)
    }

    // BC 的 RemoveChildlessPolicyNodes
    fn remove_childless(&mut self, depth_limit: usize) {
        if !self.valid {
            return;
        }
        for i in (0..depth_limit).rev() {
            let mut j = self.levels[i].len();
            while j > 0 {
                j -= 1;
                let node = self.levels[i][j];
                if !self.tree.node(node).children.is_empty() {
                    continue;
                }
                self.levels[i].remove(j);
                match self.tree.node(node).parent {
                    Some(parent) => self.tree.remove_child(parent, node),
                    None => {
                        self.valid = false;
                        return;
                    }
                }
            }
        }
    }

    // BC 的 RemovePolicyNode
    fn remove(&mut self, node: usize) {
        if !self.valid {
            return;
        }
        match self.tree.node(node).parent {
            None => {
                for level in &mut self.levels {
                    level.clear();
                }
                self.valid = false;
            }
            Some(parent) => {
                self.tree.remove_child(parent, node);
                self.remove_recurse(node);
            }
        }
    }

    fn remove_recurse(&mut self, node: usize) {
        let depth = self.tree.node(node).depth;
        self.levels[depth].retain(|&other| other != node);
        let children = self.tree.node(node).children.clone();
        for child in children {
            self.remove_recurse(child);
        }
    }

    fn check_size(&self) -> Result<()> {
        let total: usize = self.levels.iter().map(Vec::len).sum();
        if total > MAX_POLICY_NODES {
            return Err(error(
                format!("certificate policy tree exceeds {MAX_POLICY_NODES} nodes"),
                None,
                ValidatorReason::LimitExceeded,
            ));
        }
        Ok(())
    }
}

// BC 的 ProcessCertD
fn process_cert_d(
    path: &PkixCertPath,
    index: usize,
    acceptable_policies: &mut BTreeSet<Asn1Oid>,
    policy: &mut PolicyState,
    inhibit_any_policy: usize,
    for_crl_check: bool,
) -> Result<()> {
    let certs = path.certificates();
    let cert = &certs[index];
    let n = certs.len();
    let i = n - index;
    let policies = certificate_policies(cert, index)?;
    let Some(policies) = policies.filter(|_| policy.valid) else {
        policy.valid = false;
        return Ok(());
    };
    let any = any_policy();

    // (d) (1)
    let mut pols = BTreeSet::new();
    for information in policies.policies() {
        let id = information.policy_identifier();
        pols.insert(id.clone());
        if *id == any {
            continue;
        }
        let qualifiers = information.policy_qualifiers().to_vec();
        let matched = policy.levels[i - 1]
            .iter()
            .copied()
            .find(|&node| policy.tree.node(node).expected_policies.contains(id));
        if let Some(parent) = matched {
            policy.add(
                parent,
                i,
                id.clone(),
                BTreeSet::from([id.clone()]),
                qualifiers,
                false,
            );
        } else if let Some(any_node) = policy.find(i - 1, &any) {
            policy.add(
                any_node,
                i,
                id.clone(),
                BTreeSet::from([id.clone()]),
                qualifiers,
                false,
            );
        }
    }
    if acceptable_policies.is_empty() || acceptable_policies.contains(&any) {
        *acceptable_policies = pols;
    } else {
        acceptable_policies.retain(|p| pols.contains(p));
    }

    // (d) (2)
    if inhibit_any_policy > 0 || ((i < n || for_crl_check) && is_self_issued(cert)) {
        if let Some(information) = policies
            .policies()
            .iter()
            .find(|p| *p.policy_identifier() == any)
        {
            let qualifiers = information.policy_qualifiers().to_vec();
            for node in policy.levels[i - 1].clone() {
                let expected = policy.tree.node(node).expected_policies.clone();
                for expected_policy in expected {
                    let exists = policy
                        .tree
                        .node(node)
                        .children
                        .iter()
                        .any(|&child| policy.tree.node(child).valid_policy == expected_policy);
                    if !exists {
                        policy.add(
                            node,
                            i,
                            expected_policy.clone(),
                            BTreeSet::from([expected_policy]),
                            qualifiers.clone(),
                            false,
                        );
                    }
                }
            }
        }
    }

    // (d) (3)
    policy.remove_childless(i);
    // (d) (4)
    if has_critical_extension(cert, &ExtensionId::CERTIFICATE_POLICIES.oid()) {
        for node in policy.levels[i].clone() {
            policy.tree.node_mut(node).critical = true;
        }
    }
    policy.check_size()
}

// BC 的 ProcessCertE：沒有 certificatePolicies 時，樹變成 null
fn process_cert_e(path: &PkixCertPath, index: usize, policy: &mut PolicyState) -> Result<()> {
    if certificate_policies(&path.certificates()[index], index)?.is_none() {
        policy.valid = false;
    }
    Ok(())
}

// BC 的 PrepareCertB：policyMappings
fn prepare_cert_b(
    path: &PkixCertPath,
    index: usize,
    policy: &mut PolicyState,
    policy_mapping: usize,
) -> Result<()> {
    let certs = path.certificates();
    let cert = &certs[index];
    let i = certs.len() - index;
    let Some(mappings) = policy_mappings(cert, index)? else {
        return Ok(());
    };
    // 保持 BC Dictionary 的插入順序
    let mut by_issuer: Vec<(Asn1Oid, BTreeSet<Asn1Oid>)> = Vec::new();
    for (issuer, subject) in mappings {
        match by_issuer.iter_mut().find(|(id, _)| *id == issuer) {
            Some((_, subjects)) => {
                subjects.insert(subject);
            }
            None => by_issuer.push((issuer, BTreeSet::from([subject]))),
        }
    }
    let any = any_policy();
    for (id_p, expected) in by_issuer {
        // (2)
        if policy_mapping == 0 {
            let mut j = policy.levels[i].len();
            while j > 0 {
                j -= 1;
                let node = policy.levels[i][j];
                if policy.tree.node(node).valid_policy == id_p {
                    if let Some(parent) = policy.tree.node(node).parent {
                        policy.tree.remove_child(parent, node);
                    }
                    policy.levels[i].remove(j);
                }
            }
            policy.remove_childless(i);
            continue;
        }
        // (1)
        if let Some(node) = policy.find(i, &id_p) {
            policy.tree.node_mut(node).expected_policies = expected;
            continue;
        }
        let Some(any_node) = policy.find(i, &any) else {
            continue;
        };
        let policies = certificate_policies(cert, index)?;
        let qualifiers = policies
            .iter()
            .flat_map(|p| p.policies())
            .find(|p| *p.policy_identifier() == any)
            .map(|p| p.policy_qualifiers().to_vec())
            .unwrap_or_default();
        let critical = has_critical_extension(cert, &ExtensionId::CERTIFICATE_POLICIES.oid());
        if let Some(parent) = policy.tree.node(any_node).parent {
            if policy.tree.node(parent).valid_policy == any {
                policy.add(parent, i, id_p, expected, qualifiers, critical);
            }
        }
    }
    Ok(())
}

// BC 的 WrapupCertG：與 user-initial-policy-set 取交集
fn wrapup_cert_g(
    params: &PkixParameters,
    n: usize,
    index: usize,
    policy: &mut PolicyState,
    acceptable_policies: &BTreeSet<Asn1Oid>,
) -> Result<Option<PolicyTree>> {
    let initial = params.initial_policies();
    let any = any_policy();
    if !policy.valid {
        if params.is_explicit_policy_required() {
            return Err(error(
                "Explicit policy requested but none available.",
                Some(index),
                ValidatorReason::InvalidPolicy,
            ));
        }
        return Ok(None);
    }
    if initial.is_empty() || initial.contains(&any) {
        if params.is_explicit_policy_required() {
            if acceptable_policies.is_empty() {
                return Err(error(
                    "Explicit policy requested but none available.",
                    Some(index),
                    ValidatorReason::InvalidPolicy,
                ));
            }
            policy.remove_childless(n);
        }
    } else {
        let mut valid_nodes = Vec::new();
        for level in &policy.levels {
            for &node in level {
                if policy.tree.node(node).valid_policy != any {
                    continue;
                }
                for &child in &policy.tree.node(node).children {
                    if policy.tree.node(child).valid_policy != any && !valid_nodes.contains(&child)
                    {
                        valid_nodes.push(child);
                    }
                }
            }
        }
        for node in valid_nodes {
            if !initial.contains(&policy.tree.node(node).valid_policy) {
                policy.remove(node);
            }
        }
        policy.remove_childless(n);
    }
    Ok(policy.valid.then(|| policy.tree.clone()))
}
