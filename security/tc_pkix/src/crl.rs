use std::cell::RefCell;
use std::cmp::Ordering;
use std::sync::Arc;

use tc_asn1::{Asn1Enumerated, Asn1Integer};
use tc_asn1_x500::Name;
use tc_asn1_x509::cert::{SubjectPublicKeyInfo, Time};
use tc_asn1_x509::crl::{
    CrlDistributionPoints, CrlNumber, DistributionPoint, DistributionPointName,
    IssuingDistributionPoint, ReasonFlags,
};
use tc_asn1_x509::ext::{AuthorityKeyIdentifier, BasicConstraints, ExtensionId, KeyUsage};
use tc_asn1_x509::name::{GeneralName, GeneralNames};
use tc_x509::X509Operator;
use tc_x509::cert::X509Certificate;
use tc_x509::crl::X509Crl;

use crate::builder::PkixCertPathBuilder;
use crate::util::{
    certificate_extension, crl_extension, crl_has_critical_extension, error, next_working_key,
    verify_crl,
};
use crate::{
    CertPathValidatorError, PkixBuilderParameters, PkixParameters, ValidatorReason, ValidityModel,
};

type Source = Box<dyn std::error::Error + Send + Sync>;

// CRL 檢查內部的失敗：Plain 對應 BC 的一般 Exception，會被下一個 CRL 或分發點吸收；Validator 對應
// PkixCertPathValidatorException，直接往外傳；Recoverable 是找不到 CRL
enum CrlError {
    Plain(String, Option<Source>),
    Validator(CertPathValidatorError),
    Recoverable(CertPathValidatorError),
}

impl CrlError {
    fn plain(message: impl Into<String>) -> Self {
        Self::Plain(message.into(), None)
    }

    fn with(message: impl Into<String>, source: impl Into<Source>) -> Self {
        Self::Plain(message.into(), Some(source.into()))
    }

    fn message(&self) -> String {
        match self {
            Self::Plain(message, _) => message.clone(),
            Self::Validator(e) | Self::Recoverable(e) => e.message().to_owned(),
        }
    }
}

type Result<T> = std::result::Result<T, CrlError>;

// BC 的 ReasonsMask；位元與 ReasonFlags 相同
#[derive(Clone, Copy, Default)]
struct ReasonsMask(u32);

// unused 到 aACompromise 的九個位元，與 ReasonFlags 的 bits 相同
const ALL_REASONS: u32 = 0xff80_0000;

impl ReasonsMask {
    fn is_all(self) -> bool {
        ALL_REASONS & !self.0 == 0
    }

    fn has_new(self, other: ReasonsMask) -> bool {
        other.0 & !self.0 != 0
    }

    fn add(&mut self, other: ReasonsMask) {
        self.0 |= other.0;
    }
}

const REASON_NAMES: [&str; 11] = [
    "unspecified",
    "keyCompromise",
    "cACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "unknown",
    "removeFromCRL",
    "privilegeWithdrawn",
    "aACompromise",
];
const REMOVE_FROM_CRL: i64 = 8;

fn is_reason_known(code: i64) -> bool {
    (0..=10).contains(&code) && code != 7
}

fn reason_of(code: Option<i64>) -> i64 {
    code.filter(|&c| is_reason_known(c)).unwrap_or(0)
}

// BC 的 CrlCertStatus
#[derive(Default)]
struct CertStatus {
    revocation_date: Option<Time>,
    reason_code: Option<i64>,
}

impl CertStatus {
    fn is_revoked(&self) -> bool {
        self.revocation_date.is_some()
    }

    fn reason_text(&self) -> String {
        match self.reason_code {
            Some(code) if !is_reason_known(code) => format!("(unknown code: {code})"),
            code => REASON_NAMES[reason_of(code) as usize].to_owned(),
        }
    }
}

// BC 的 yyyy-MM-dd HH:mm:ss K
fn revocation_text(time: Time) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} Z",
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

// BC 的 CheckCrls：對每個分發點找 CRL，直到確定撤銷或所有理由都涵蓋；最後以憑證的簽發者為預設分發點
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_crls(
    x509: &Arc<dyn X509Operator>,
    index: usize,
    params: &PkixParameters,
    cert: &X509Certificate,
    current_date: Time,
    validity_date: Time,
    sign: Option<&X509Certificate>,
    working_public_key: &SubjectPublicKeyInfo,
    certs: &[X509Certificate],
) -> std::result::Result<(), CertPathValidatorError> {
    let context = Context {
        x509,
        index,
        params,
        cert,
        current_date,
        validity_date,
        sign,
        working_public_key,
        certs,
    };
    context.check_crls().map_err(|e| match e {
        CrlError::Plain(message, source) => {
            let error = error(message, Some(index), ValidatorReason::Unspecified);
            match source {
                Some(source) => error.with_source(source),
                None => error,
            }
        }
        CrlError::Validator(e) | CrlError::Recoverable(e) => e,
    })
}

struct Context<'a> {
    x509: &'a Arc<dyn X509Operator>,
    index: usize,
    params: &'a PkixParameters,
    cert: &'a X509Certificate,
    current_date: Time,
    validity_date: Time,
    sign: Option<&'a X509Certificate>,
    working_public_key: &'a SubjectPublicKeyInfo,
    certs: &'a [X509Certificate],
}

impl Context<'_> {
    fn check_crls(&self) -> Result<()> {
        let crl_dp: Option<CrlDistributionPoints> =
            certificate_extension(self.cert, &ExtensionId::CRL_DISTRIBUTION_POINTS.oid()).map_err(
                |e| CrlError::with("CRL distribution point extension could not be read.", e),
            )?;
        let mut status = CertStatus::default();
        let mut reasons = ReasonsMask::default();
        let mut last: Option<CrlError> = None;
        let mut valid_crl_found = false;

        for dp in crl_dp.iter().flat_map(|c| c.points()) {
            if status.is_revoked() || reasons.is_all() {
                break;
            }
            match self.check_crl(dp, &mut status, &mut reasons) {
                Ok(()) => valid_crl_found = true,
                Err(e @ CrlError::Plain(..)) => last = Some(e),
                Err(e) => return Err(e),
            }
        }

        // 憑證沒有分發點，或分發點沒有涵蓋所有理由時，以簽發者的 DN 當分發點
        if !status.is_revoked() && !reasons.is_all() {
            let issuer =
                GeneralNames::new(vec![GeneralName::DirectoryName(self.cert.issuer().clone())])
                    .map_err(|e| CrlError::with("Could not read certificate issuer.", e))?;
            let dp =
                DistributionPoint::new(Some(DistributionPointName::FullName(issuer)), None, None)
                    .map_err(|e| CrlError::with("Could not read certificate issuer.", e))?;
            match self.check_crl(&dp, &mut status, &mut reasons) {
                Ok(()) => valid_crl_found = true,
                Err(e @ CrlError::Plain(..)) => last = Some(e),
                Err(CrlError::Recoverable(e)) if last.is_some() => {
                    let tried = last.as_ref().map(CrlError::message).unwrap_or_default();
                    return Err(CrlError::Recoverable(error(
                        format!(
                            "{}. The CRL distribution points of the certificate were tried first and failed: {tried}",
                            e.message()
                        ),
                        e.index(),
                        e.reason(),
                    )));
                }
                Err(e) => return Err(e),
            }
        }

        if !valid_crl_found {
            let last = last.unwrap_or_else(|| CrlError::plain("No valid CRL found."));
            let (message, source) = match last {
                CrlError::Plain(message, source) => (message, source),
                CrlError::Validator(e) | CrlError::Recoverable(e) => (e.message().to_owned(), None),
            };
            let error = error(
                message,
                Some(self.index),
                ValidatorReason::UndeterminedRevocationStatus,
            );
            return Err(CrlError::Validator(match source {
                Some(source) => error.with_source(source),
                None => error,
            }));
        }
        match status.revocation_date {
            None if !reasons.is_all() => Err(CrlError::Validator(error(
                "Certificate status could not be determined.",
                Some(self.index),
                ValidatorReason::UndeterminedRevocationStatus,
            ))),
            None => Ok(()),
            Some(date) => Err(CrlError::Validator(error(
                format!(
                    "Certificate revocation after {}, reason: {}",
                    revocation_text(date),
                    status.reason_text()
                ),
                Some(self.index),
                ValidatorReason::Revoked,
            ))),
        }
    }

    // BC 的 CheckCrl：一個分發點
    fn check_crl(
        &self,
        dp: &DistributionPoint,
        status: &mut CertStatus,
        reasons: &mut ReasonsMask,
    ) -> Result<()> {
        if self.validity_date > self.current_date {
            return Err(CrlError::plain("Validation time is in future."));
        }
        let crls = self.complete_crls(dp)?;
        let mut valid_crl_found = false;
        let mut last = None;
        for crl in &crls {
            if status.is_revoked() || reasons.is_all() {
                break;
            }
            match self.check_one_crl(dp, crl, status, reasons) {
                Ok(true) => valid_crl_found = true,
                Ok(false) => {}
                Err(e @ CrlError::Plain(..)) => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        if !valid_crl_found {
            return Err(last.unwrap_or_else(|| CrlError::plain("No valid CRL found.")));
        }
        Ok(())
    }

    // 一份完整 CRL；false 表示它沒有新的理由，略過
    fn check_one_crl(
        &self,
        dp: &DistributionPoint,
        crl: &X509Crl,
        status: &mut CertStatus,
        reasons: &mut ReasonsMask,
    ) -> Result<bool> {
        check_crl_critical_extensions(crl, "CRL contains unsupported critical extensions.")?;
        // (d)
        let interim = process_crl_d(crl, dp)?;
        // (e)
        if !reasons.has_new(interim) {
            return Ok(false);
        }
        // (f)
        let keys = self.process_crl_f(crl)?;
        // (g)
        let key = self.process_crl_g(crl, &keys)?;
        // CRL 必須在目前時間有效，不只是驗證時間
        if self.params.validity_model() != ValidityModel::Chain
            && self.cert.not_after() < crl.this_update()
        {
            return Err(CrlError::plain("No valid CRL for current time found."));
        }
        process_crl_b1(dp, self.cert, crl)?;
        process_crl_b2(dp, self.cert, crl)?;
        if self.params.is_use_deltas_enabled() {
            let deltas = self.delta_crls(crl)?;
            // (h)
            if let Some(delta) = self.process_crl_h(&deltas, &key)? {
                check_crl_critical_extensions(
                    delta,
                    "Delta CRL contains unsupported critical extensions.",
                )?;
                // (c)
                process_crl_c(delta, crl)?;
                // (i)
                cert_status(self.validity_date, delta, self.cert, status)?;
            }
        }
        // (j)
        if !status.is_revoked() {
            cert_status(self.validity_date, crl, self.cert, status)?;
        }
        // (k)
        if status.is_revoked() && reason_of(status.reason_code) == REMOVE_FROM_CRL {
            *status = CertStatus::default();
        }
        reasons.add(interim);
        Ok(true)
    }

    // BC 的 GetCompleteCrls 加上 PkixCrlUtilities.ImplFindCrls 的時間過濾
    fn complete_crls(&self, dp: &DistributionPoint) -> Result<Vec<&X509Crl>> {
        let issuers = crl_issuers(dp, self.cert.issuer()).map_err(|e| {
            CrlError::Plain(
                "Could not get issuer information from distribution point.".into(),
                Some(e),
            )
        })?;
        let mut crls: Vec<&X509Crl> = Vec::new();
        for crl in self
            .params
            .crl_stores()
            .iter()
            .flat_map(|store| store.crls())
        {
            if !issuers.iter().any(|issuer| issuer.equivalent(crl.issuer())) {
                continue;
            }
            // CompleteCrlEnabled：帶 deltaCRLIndicator 的不算
            if crl
                .extensions()
                .and_then(|e| e.get(ExtensionId::DELTA_CRL_INDICATOR))
                .is_some()
            {
                continue;
            }
            if !self.fresh(crl, true) || crls.iter().any(|c| *c == crl) {
                continue;
            }
            crls.push(crl);
        }
        if crls.is_empty() {
            return Err(CrlError::Recoverable(error(
                format!("No CRLs found for issuer \"{}\"", self.cert.issuer()),
                Some(self.index),
                ValidatorReason::UndeterminedRevocationStatus,
            )));
        }
        Ok(crls)
    }

    fn fresh(&self, crl: &X509Crl, checking_certificate: bool) -> bool {
        crl.next_update()
            .is_none_or(|next| next > self.validity_date)
            && (!checking_certificate || crl.this_update() < self.cert.not_after())
    }

    // BC 的 GetDeltaCrls：同簽發者、CRL 編號較新、基準編號不超過完整 CRL、IDP 相同的 delta CRL
    fn delta_crls(&self, complete: &X509Crl) -> Result<Vec<&X509Crl>> {
        let complete_number: Option<CrlNumber> =
            crl_extension(complete, &ExtensionId::CRL_NUMBER.oid()).map_err(|e| {
                CrlError::with("CRL number extension could not be extracted from CRL.", e)
            })?;
        let complete_idp: Option<IssuingDistributionPoint> =
            crl_extension(complete, &ExtensionId::ISSUING_DISTRIBUTION_POINT.oid()).map_err(
                |e| {
                    CrlError::with(
                        "Issuing distribution point extension value could not be read.",
                        e,
                    )
                },
            )?;
        let idp_value = |crl: &X509Crl| {
            crl.extensions()
                .and_then(|e| e.get(ExtensionId::ISSUING_DISTRIBUTION_POINT))
                .map(|e| e.extn_value().to_vec())
        };
        let complete_idp_value = complete_idp
            .as_ref()
            .map(|_| idp_value(complete).unwrap_or_default());
        let mut deltas: Vec<&X509Crl> = Vec::new();
        for crl in self
            .params
            .crl_stores()
            .iter()
            .flat_map(|store| store.crls())
        {
            if !complete.issuer().equivalent(crl.issuer()) {
                continue;
            }
            if let Some(complete_number) = &complete_number {
                let number: Option<CrlNumber> =
                    match crl_extension(crl, &ExtensionId::CRL_NUMBER.oid()) {
                        Ok(number) => number,
                        Err(_) => continue,
                    };
                let Some(number) = number else { continue };
                if compare(number.number(), complete_number.number()) != Some(Ordering::Greater) {
                    continue;
                }
            }
            let base: Option<CrlNumber> =
                match crl_extension(crl, &ExtensionId::DELTA_CRL_INDICATOR.oid()) {
                    Ok(base) => base,
                    Err(_) => continue,
                };
            let Some(base) = base else { continue };
            if let Some(complete_number) = &complete_number {
                if compare(base.number(), complete_number.number()) == Some(Ordering::Greater) {
                    continue;
                }
            }
            if idp_value(crl) != complete_idp_value {
                continue;
            }
            if !self.fresh(crl, false) || deltas.iter().any(|c| *c == crl) {
                continue;
            }
            // 只留關鍵的 deltaCRLIndicator
            if crl_has_critical_extension(crl, &ExtensionId::DELTA_CRL_INDICATOR.oid()) {
                deltas.push(crl);
            }
        }
        Ok(deltas)
    }

    // BC 的 ProcessCrlF：找出可能簽發這份 CRL 的憑證，並確認它們的路徑出自同一個信任錨
    fn process_crl_f(&self, crl: &X509Crl) -> Result<Vec<SubjectPublicKeyInfo>> {
        let aki: Option<AuthorityKeyIdentifier> = crl_extension(crl, &ExtensionId::AUTHORITY_KEY_IDENTIFIER.oid())
            .map_err(|e| {
                CrlError::with(
                    "Subject criteria for certificate selector to find issuer certificate for CRL could not be set.",
                    e,
                )
            })?;
        let key_id = aki
            .as_ref()
            .and_then(|a| a.key_identifier())
            .map(<[u8]>::to_vec);
        let mut candidates: Vec<&X509Certificate> = Vec::new();
        for candidate in self
            .params
            .certificate_stores()
            .iter()
            .flat_map(|s| s.certificates())
        {
            if !candidate.subject().equivalent(crl.issuer()) {
                continue;
            }
            if let Some(key_id) = &key_id {
                let ski = certificate_extension::<tc_asn1_x509::ext::SubjectKeyIdentifier>(
                    candidate,
                    &ExtensionId::SUBJECT_KEY_IDENTIFIER.oid(),
                );
                if !matches!(ski, Ok(Some(ski)) if ski.key_identifier() == key_id.as_slice()) {
                    continue;
                }
            }
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }

        // 這張憑證的 CA 自己簽的 CRL：路徑已經驗過，直接用它的公鑰
        let mut valid: Vec<(Option<&X509Certificate>, SubjectPublicKeyInfo)> =
            vec![(self.sign, self.working_public_key.clone())];
        let mut signer_last: Option<CrlError> = None;
        for candidate in candidates {
            if Some(candidate) == self.sign {
                continue;
            }
            if !crl_signer_enter(candidate) {
                valid.push((Some(candidate), candidate.subject_public_key_info().clone()));
                continue;
            }
            let outcome = self.signer_key(candidate);
            crl_signer_exit(candidate);
            match outcome {
                Ok(key) => valid.push((Some(candidate), key)),
                Err(e) => signer_last = Some(e),
            }
        }

        let mut keys = Vec::new();
        let mut last = None;
        for (certificate, key) in valid {
            let usage: Option<KeyUsage> = certificate
                .map(|c| certificate_extension(c, &ExtensionId::KEY_USAGE.oid()))
                .transpose()
                .ok()
                .flatten()
                .flatten();
            if usage.is_some_and(|usage| !usage.contains(KeyUsage::CRL_SIGN)) {
                last = Some(CrlError::plain(
                    "Issuer certificate key usage extension does not permit CRL signing.",
                ));
            } else if !keys.contains(&key) {
                keys.push(key);
            }
        }
        if keys.is_empty() {
            return Err(signer_last
                .or(last)
                .unwrap_or_else(|| CrlError::plain("Cannot find a valid issuer certificate.")));
        }
        Ok(keys)
    }

    // 為 CRL 簽發者建一條路徑；路徑上已有的憑證不再檢查撤銷
    fn signer_key(&self, signer: &X509Certificate) -> Result<SubjectPublicKeyInfo> {
        let revocation = !self.certs.contains(signer);
        let params = self
            .params
            .clone()
            .with_target_constraints(None)
            .with_target_certificate(Some(signer.clone()))
            .with_revocation_enabled(revocation);
        let builder = PkixCertPathBuilder::for_crl_check(self.x509.clone());
        let built = builder.build(&PkixBuilderParameters::new(params)).map_err(|e| {
            CrlError::with(
                "CertPath for CRL signer failed to validate. Per RFC 5280 sec. 6.3.3 (f) the CRL issuer's \
                 certification path must be anchored at the same trust anchor as the certificate being checked.",
                e,
            )
        })?;
        next_working_key(built.cert_path().certificates(), 0).map_err(|e| {
            CrlError::with(
                "Public key of issuer certificate of CRL could not be retrieved.",
                e,
            )
        })
    }

    fn process_crl_g(
        &self,
        crl: &X509Crl,
        keys: &[SubjectPublicKeyInfo],
    ) -> Result<SubjectPublicKeyInfo> {
        let mut last = None;
        for key in keys {
            match verify_crl(&**self.x509, crl, key) {
                Ok(()) => return Ok(key.clone()),
                Err(e) => last = Some(e),
            }
        }
        Err(match last {
            Some(e) => CrlError::with("Cannot verify CRL.", e),
            None => CrlError::plain("Cannot verify CRL."),
        })
    }

    fn process_crl_h<'c>(
        &self,
        deltas: &[&'c X509Crl],
        key: &SubjectPublicKeyInfo,
    ) -> Result<Option<&'c X509Crl>> {
        let mut last = None;
        for delta in deltas {
            match verify_crl(&**self.x509, delta, key) {
                Ok(()) => return Ok(Some(delta)),
                Err(e) => last = Some(e),
            }
        }
        match last {
            Some(e) => Err(CrlError::with("Cannot verify delta CRL.", e)),
            None => Ok(None),
        }
    }
}

thread_local! {
    // BC 的 CrlSignersInProgress：避免候選簽發者互相遞迴建立路徑
    static CRL_SIGNERS: RefCell<Vec<X509Certificate>> = const { RefCell::new(Vec::new()) };
}

fn crl_signer_enter(certificate: &X509Certificate) -> bool {
    CRL_SIGNERS.with(|signers| {
        let mut signers = signers.borrow_mut();
        if signers.contains(certificate) {
            false
        } else {
            signers.push(certificate.clone());
            true
        }
    })
}

fn crl_signer_exit(certificate: &X509Certificate) {
    CRL_SIGNERS.with(|signers| signers.borrow_mut().retain(|c| c != certificate));
}

// BC 的 GetCrlIssuersFromDistributionPoint
fn crl_issuers(
    dp: &DistributionPoint,
    cert_issuer: &Name,
) -> std::result::Result<Vec<Name>, Source> {
    if let Some(crl_issuer) = dp.crl_issuer() {
        return Ok(crl_issuer
            .names()
            .iter()
            .filter_map(|name| match name {
                GeneralName::DirectoryName(dn) => Some(dn.clone()),
                _ => None,
            })
            .collect());
    }
    if dp.distribution_point().is_none() {
        return Err(
            "CRL issuer is omitted from distribution point but no distributionPoint field present."
                .into(),
        );
    }
    Ok(vec![cert_issuer.clone()])
}

fn check_crl_critical_extensions(crl: &X509Crl, message: &str) -> Result<()> {
    let allowed = [
        ExtensionId::ISSUING_DISTRIBUTION_POINT.oid(),
        ExtensionId::DELTA_CRL_INDICATOR.oid(),
    ];
    let unsupported = crl.extensions().is_some_and(|extensions| {
        extensions
            .extensions()
            .iter()
            .any(|e| e.critical() && !allowed.contains(e.extn_id()))
    });
    if unsupported {
        return Err(CrlError::plain(message));
    }
    Ok(())
}

fn issuing_distribution_point(
    crl: &X509Crl,
    message: &str,
) -> Result<Option<IssuingDistributionPoint>> {
    crl_extension(crl, &ExtensionId::ISSUING_DISTRIBUTION_POINT.oid())
        .map_err(|e| CrlError::with(message, e))
}

// BC 的 ProcessCrlD：IDP 與分發點的理由取交集，沒寫的是全部
fn process_crl_d(crl: &X509Crl, dp: &DistributionPoint) -> Result<ReasonsMask> {
    let idp = issuing_distribution_point(
        crl,
        "issuing distribution point extension could not be decoded.",
    )?;
    let idp_flags = idp
        .and_then(|i| i.only_some_reasons())
        .map_or(ALL_REASONS, ReasonFlags::bits);
    let dp_flags = dp.reasons().map_or(ALL_REASONS, ReasonFlags::bits);
    Ok(ReasonsMask(idp_flags & dp_flags))
}

// BC 的 ProcessCrlB1：CRL 的簽發者要是分發點的 cRLIssuer，或憑證的簽發者
fn process_crl_b1(dp: &DistributionPoint, cert: &X509Certificate, crl: &X509Crl) -> Result<()> {
    let idp = issuing_distribution_point(
        crl,
        "Issuing distribution point extension could not be decoded.",
    )?;
    let indirect = idp.is_some_and(|i| i.indirect_crl());
    let matched = match dp.crl_issuer() {
        Some(crl_issuer) => {
            let matched = crl_issuer
                .names()
                .iter()
                .any(|name| matches!(name, GeneralName::DirectoryName(dn) if dn == crl.issuer()));
            if matched && !indirect {
                return Err(CrlError::plain(
                    "Distribution point contains cRLIssuer field but CRL is not indirect.",
                ));
            }
            if !matched {
                return Err(CrlError::plain(
                    "CRL issuer of CRL does not match CRL issuer of distribution point.",
                ));
            }
            true
        }
        None => crl.issuer().equivalent(cert.issuer()),
    };
    if !matched {
        return Err(CrlError::plain(
            "Cannot find matching CRL issuer for certificate.",
        ));
    }
    Ok(())
}

fn append_rdn(name: &Name, dp_name: &DistributionPointName) -> Option<GeneralName> {
    match dp_name {
        DistributionPointName::NameRelativeToCrlIssuer(rdn) => {
            let mut rdns = name.rdns().to_vec();
            rdns.push(rdn.clone());
            Some(GeneralName::DirectoryName(Name::new(rdns)))
        }
        _ => None,
    }
}

// BC 的 ProcessCrlB2：IDP 的名稱與範圍
fn process_crl_b2(dp: &DistributionPoint, cert: &X509Certificate, crl: &X509Crl) -> Result<()> {
    let Some(idp) = issuing_distribution_point(
        crl,
        "0 Issuing distribution point extension could not be decoded.",
    )?
    else {
        return Ok(());
    };
    if let Some(idp_name) = idp.distribution_point() {
        let mut names: Vec<GeneralName> = Vec::new();
        match idp_name {
            DistributionPointName::FullName(full) => names.extend(full.names().iter().cloned()),
            relative => names.extend(append_rdn(crl.issuer(), relative)),
        }
        let describe = |list: &[GeneralName]| format!("{list:?}");
        if let Some(dp_name) = dp.distribution_point() {
            let dp_names: Vec<GeneralName> = match dp_name {
                DistributionPointName::FullName(full) => full.names().to_vec(),
                relative => {
                    let bases: Vec<Name> = match dp.crl_issuer() {
                        Some(issuers) => issuers
                            .names()
                            .iter()
                            .filter_map(|n| match n {
                                GeneralName::DirectoryName(dn) => Some(dn.clone()),
                                _ => None,
                            })
                            .collect(),
                        None => vec![cert.issuer().clone()],
                    };
                    bases
                        .iter()
                        .filter_map(|base| append_rdn(base, relative))
                        .collect()
                }
            };
            if !dp_names.iter().any(|name| names.contains(name)) {
                return Err(CrlError::plain(format!(
                    "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point. \
                     cert DP names: {}; CRL IDP names: {}",
                    describe(&dp_names),
                    describe(&names)
                )));
            }
        } else {
            let Some(crl_issuer) = dp.crl_issuer() else {
                return Err(CrlError::plain(
                    "Either the cRLIssuer or the distributionPoint field must be contained in DistributionPoint.",
                ));
            };
            if !crl_issuer.names().iter().any(|name| names.contains(name)) {
                return Err(CrlError::plain(format!(
                    "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point. \
                     cert cRLIssuer names: {}; CRL IDP names: {}",
                    describe(crl_issuer.names()),
                    describe(&names)
                )));
            }
        }
    }
    let constraints: Option<BasicConstraints> =
        certificate_extension(cert, &ExtensionId::BASIC_CONSTRAINTS.oid())
            .map_err(|e| CrlError::with("Basic constraints extension could not be decoded.", e))?;
    if constraints.is_some_and(|bc| bc.is_ca()) {
        if idp.only_contains_user_certs() {
            return Err(CrlError::plain(
                "CA Cert CRL only contains user certificates.",
            ));
        }
    } else if idp.only_contains_ca_certs() {
        return Err(CrlError::plain("End CRL only contains CA certificates."));
    }
    if idp.only_contains_attribute_certs() {
        return Err(CrlError::plain(
            "onlyContainsAttributeCerts boolean is asserted.",
        ));
    }
    Ok(())
}

// BC 的 ProcessCrlC：delta CRL 與完整 CRL 必須同簽發者、同 IDP、同 AKI
fn process_crl_c(delta: &X509Crl, complete: &X509Crl) -> Result<()> {
    let complete_idp = issuing_distribution_point(
        complete,
        "Issuing distribution point extension could not be decoded.",
    )?;
    if !delta.issuer().equivalent(complete.issuer()) {
        return Err(CrlError::plain(
            "Complete CRL issuer does not match delta CRL issuer.",
        ));
    }
    let delta_idp = issuing_distribution_point(
        delta,
        "Issuing distribution point extension from delta CRL could not be decoded.",
    )?;
    if complete_idp != delta_idp {
        return Err(CrlError::plain(
            "Issuing distribution point extension from delta CRL and complete CRL does not match.",
        ));
    }
    let complete_aki: Option<AuthorityKeyIdentifier> =
        crl_extension(complete, &ExtensionId::AUTHORITY_KEY_IDENTIFIER.oid()).map_err(|e| {
            CrlError::with(
                "Authority key identifier extension could not be extracted from complete CRL.",
                e,
            )
        })?;
    let delta_aki: Option<AuthorityKeyIdentifier> =
        crl_extension(delta, &ExtensionId::AUTHORITY_KEY_IDENTIFIER.oid()).map_err(|e| {
            CrlError::with(
                "Authority key identifier extension could not be extracted from delta CRL.",
                e,
            )
        })?;
    let Some(complete_aki) = complete_aki else {
        return Err(CrlError::plain("CRL authority key identifier is null."));
    };
    let Some(delta_aki) = delta_aki else {
        return Err(CrlError::plain(
            "Delta CRL authority key identifier is null.",
        ));
    };
    if complete_aki != delta_aki {
        return Err(CrlError::plain(
            "Delta CRL authority key identifier does not match complete CRL authority key identifier.",
        ));
    }
    Ok(())
}

// BC 的 GetCertStatus
fn cert_status(
    valid_date: Time,
    crl: &X509Crl,
    cert: &X509Certificate,
    status: &mut CertStatus,
) -> Result<()> {
    let Some(entry) = crl.revoked_certificate_of(cert) else {
        return Ok(());
    };
    let mut reason_code = None;
    if let Some(extensions) = entry.extensions() {
        if extensions.extensions().iter().any(|e| e.critical()) {
            return Err(CrlError::plain(
                "CRL entry has unsupported critical extensions.",
            ));
        }
        let mut context = tc_asn1::DecodingContext::new(tc_asn1::DecodingOptions::default());
        let code: Option<Asn1Enumerated> = extensions
            .get_as(ExtensionId::CRL_REASONS, &mut context)
            .map_err(|e| {
                CrlError::with("Reason code CRL entry extension could not be decoded.", e)
            })?;
        reason_code = code.and_then(|code| i64::try_from(&code).ok());
    }
    let revocation_date = entry.revocation_date();
    let reason = reason_of(reason_code);
    // keyCompromise、cACompromise、aACompromise 與 unspecified 不論日期都生效
    if valid_date >= revocation_date || matches!(reason, 0 | 1 | 2 | 10) {
        status.revocation_date = Some(revocation_date);
        status.reason_code = reason_code;
    }
    Ok(())
}

// 正整數的大小；負數無法比較
fn compare(a: &Asn1Integer, b: &Asn1Integer) -> Option<Ordering> {
    let a = a.as_unsigned_bytes().ok()?;
    let b = b.as_unsigned_bytes().ok()?;
    let strip = |bytes: &[u8]| {
        let start = bytes
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(bytes.len());
        bytes[start..].to_vec()
    };
    let (a, b) = (strip(a), strip(b));
    Some(a.len().cmp(&b.len()).then_with(|| a.cmp(&b)))
}
