//! NIST PKITS（https://csrc.nist.gov/projects/pki-testing），照 Bouncy Castle 的 NistCertPathTest2
//! 移植：失敗時比對憑證位置、原因與訊息。BC 標為 Ignore 的案例在這裡也 ignore。
//!
//! 資料是 NIST 目前的 PKITS_data.zip，2010 年重新簽發：憑證自 2010-01-01 08:30 起生效、CRL 到 2030
//! 年，要過期的到 2011-01-01。BC 的測試資料是較早的版本，所以驗證時間改為 2012-01-01，日期也照
//! 這一版的憑證與 CRL。

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use tc_asn1::Asn1Oid;
use tc_asn1_x509::cert::Time;
use tc_pkix::{
    PkixCertPath, PkixCertPathValidator, PkixCertPathValidatorResult, PkixError, PkixParameters,
    TrustAnchor, ValidatorReason,
};
use tc_x509::cert::X509Certificate;
use tc_x509::crl::X509Crl;
use tc_x509::store::{X509CertificateStore, X509CrlStore};
use tc_x509::{DefaultX509OperatorBuilder, X509Operator, X509OperatorBuilder};

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/PKITS");

fn file_name(name: &str) -> String {
    name.replace([' ', '-'], "")
}

fn certificate(name: &str) -> X509Certificate {
    let path = format!("{DATA}/certs/{}.crt", file_name(name));
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    X509Certificate::decode(&der).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn crl(name: &str) -> X509Crl {
    let path = format!("{DATA}/crls/{}.crl", file_name(name));
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    X509Crl::decode(&der).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn x509() -> Arc<dyn X509Operator> {
    static X509: OnceLock<Arc<dyn X509Operator>> = OnceLock::new();
    X509.get_or_init(|| Arc::from(DefaultX509OperatorBuilder::default().build()))
        .clone()
}

fn policy(name: &str) -> Asn1Oid {
    let oid = match name {
        "anyPolicy" => "2.5.29.32.0".to_owned(),
        _ => match name.strip_prefix("NIST-test-policy-") {
            Some(n) => format!("2.16.840.1.101.3.2.1.48.{n}"),
            None => name.to_owned(),
        },
    };
    oid.parse().unwrap()
}

fn time(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Time {
    Time::new(year, month, day, hour, minute, second).unwrap()
}

fn revocation_date(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> String {
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} Z")
}

fn validity_date(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> String {
    format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z")
}

// BC 的 PkitsTest
struct Pkits {
    end_entity: Option<X509Certificate>,
    certs: Vec<X509Certificate>,
    crls: Vec<X509Crl>,
    policies: BTreeSet<Asn1Oid>,
    explicit_policy_required: Option<bool>,
    any_policy_inhibited: Option<bool>,
    policy_mapping_inhibited: Option<bool>,
    delta_crls: bool,
}

impl Pkits {
    fn new() -> Self {
        Self {
            end_entity: None,
            certs: Vec::new(),
            crls: vec![crl("TrustAnchorRootCRL")],
            policies: BTreeSet::new(),
            explicit_policy_required: None,
            any_policy_inhibited: None,
            policy_mapping_inhibited: None,
            delta_crls: false,
        }
    }

    fn end_entity(mut self, name: &str) -> Self {
        self.end_entity = Some(certificate(name));
        self
    }

    fn certs(mut self, names: &[&str]) -> Self {
        self.certs
            .extend(names.iter().map(|name| certificate(name)));
        self
    }

    fn crls(mut self, names: &[&str]) -> Self {
        self.crls.extend(names.iter().map(|name| crl(name)));
        self
    }

    fn policies(mut self, names: &[&str]) -> Self {
        self.policies.extend(names.iter().map(|name| policy(name)));
        self
    }

    fn explicit_policy_required(mut self, required: bool) -> Self {
        self.explicit_policy_required = Some(required);
        self
    }

    fn any_policy_inhibited(mut self, inhibited: bool) -> Self {
        self.any_policy_inhibited = Some(inhibited);
        self
    }

    fn policy_mapping_inhibited(mut self, inhibited: bool) -> Self {
        self.policy_mapping_inhibited = Some(inhibited);
        self
    }

    fn delta_crls(mut self, enabled: bool) -> Self {
        self.delta_crls = enabled;
        self
    }

    fn run(&self) -> Result<PkixCertPathValidatorResult, PkixError> {
        let mut certs = vec![self.end_entity.clone().expect("an end entity")];
        certs.extend(self.certs.iter().cloned());
        let anchor = TrustAnchor::from_certificate(certificate("TrustAnchorRootCertificate"));
        let mut params = PkixParameters::new(vec![anchor])
            .with_certificate_store(X509CertificateStore::new(certs.clone()))
            .with_crl_store(X509CrlStore::new(self.crls.clone()))
            .with_revocation_enabled(true)
            .with_date(Some(time(2012, 1, 1, 0, 0, 0)))
            .with_use_deltas(self.delta_crls);
        if let Some(required) = self.explicit_policy_required {
            params = params.with_explicit_policy_required(required);
        }
        if let Some(inhibited) = self.any_policy_inhibited {
            params = params.with_any_policy_inhibited(inhibited);
        }
        if let Some(inhibited) = self.policy_mapping_inhibited {
            params = params.with_policy_mapping_inhibited(inhibited);
        }
        if !self.policies.is_empty() {
            params = params
                .with_explicit_policy_required(true)
                .with_initial_policies(self.policies.clone());
        }
        PkixCertPathValidator::new(x509()).validate(&PkixCertPath::new(certs), &params)
    }

    fn valid(self) {
        if let Err(e) = self.run() {
            panic!("path rejected: {e}");
        }
    }

    fn failure(&self, index: Option<usize>, reason: ValidatorReason) -> String {
        match self.run() {
            Ok(_) => panic!("path accepted when should be rejected"),
            Err(PkixError::Validator(e)) => {
                assert_eq!((e.index(), e.reason()), (index, reason), "{}", e.message());
                e.message().to_owned()
            }
            Err(e) => panic!("not a validator failure: {e}"),
        }
    }

    fn invalid(self, index: Option<usize>, reason: ValidatorReason, message: &str) {
        assert_eq!(self.failure(index, reason), message);
    }

    fn invalid_prefix(self, index: Option<usize>, reason: ValidatorReason, prefix: &str) {
        let message = self.failure(index, reason);
        assert!(
            message.starts_with(prefix),
            "{message:?} does not start with {prefix:?}"
        );
    }
}

// 4.1.1 Valid Signatures Test1
#[test]
fn pkits_4_1_1_valid_signatures_test1() {
    Pkits::new()
        .end_entity("Valid Certificate Path Test1 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .valid();
}

// 4.1.2 Invalid CA Signature Test2
#[test]
fn pkits_4_1_2_invalid_ca_signature_test2() {
    Pkits::new()
        .end_entity("Invalid CA Signature Test2 EE")
        .crls(&["Bad Signed CA CRL"])
        .certs(&["Bad Signed CA Cert"])
        .invalid(
            Some(1),
            ValidatorReason::InvalidSignature,
            "TrustAnchor found but certificate validation failed.",
        );
}

// 4.1.3 Invalid EE Signature Test3
#[test]
fn pkits_4_1_3_invalid_ee_signature_test3() {
    Pkits::new()
        .end_entity("Invalid EE Signature Test3 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidSignature,
            "Could not validate certificate signature.",
        );
}

// 4.1.4 Valid DSA Signatures Test4
#[test]
fn pkits_4_1_4_valid_dsa_signatures_test4() {
    Pkits::new()
        .end_entity("Valid DSA Signatures Test4 EE")
        .crls(&["DSA CA CRL"])
        .certs(&["DSA CA Cert"])
        .valid();
}

// 4.1.5 Valid DSA Parameter Inheritance Test5
#[test]
fn pkits_4_1_5_valid_dsa_parameter_inheritance_test5() {
    Pkits::new()
        .end_entity("Valid DSA Parameter Inheritance Test5 EE")
        .crls(&["DSA Parameters Inherited CA CRL", "DSA CA CRL"])
        .certs(&["DSA Parameters Inherited CA Cert", "DSA CA Cert"])
        .valid();
}

// 4.1.6 Invalid DSA Signature Test6
#[test]
fn pkits_4_1_6_invalid_dsa_signature_test6() {
    Pkits::new()
        .end_entity("Invalid DSA Signature Test6 EE")
        .crls(&["DSA CA CRL"])
        .certs(&["DSA CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidSignature,
            "Could not validate certificate signature.",
        );
}

// 4.2.1 Invalid CA notBefore Date Test1
#[test]
fn pkits_4_2_1_invalid_ca_notbefore_date_test1() {
    let expected_date = validity_date(2047, 1, 1, 12, 1, 0);
    Pkits::new()
        .end_entity("Invalid CA notBefore Date Test1 EE")
        .crls(&["Bad notBefore Date CA CRL"])
        .certs(&["Bad notBefore Date CA Cert"])
        .invalid(
            Some(1),
            ValidatorReason::NotYetValid,
            &format!("Could not validate certificate: certificate not valid until {expected_date}"),
        );
}

// 4.2.2 Invalid EE notBefore Date Test2
#[test]
fn pkits_4_2_2_invalid_ee_notbefore_date_test2() {
    let expected_date = validity_date(2047, 1, 1, 12, 1, 0);
    Pkits::new()
        .end_entity("Invalid EE notBefore Date Test2 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::NotYetValid,
            &format!("Could not validate certificate: certificate not valid until {expected_date}"),
        );
}

// 4.2.3 Valid pre2000 UTC notBefore Date Test3
#[test]
fn pkits_4_2_3_valid_pre2000_utc_notbefore_date_test3() {
    Pkits::new()
        .end_entity("Valid pre2000 UTC notBefore Date Test3 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .valid();
}

// 4.2.4 Valid GeneralizedTime notBefore Date Test4
#[test]
fn pkits_4_2_4_valid_generalizedtime_notbefore_date_test4() {
    Pkits::new()
        .end_entity("Valid GeneralizedTime notBefore Date Test4 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .valid();
}

// 4.2.5 Invalid CA notAfter Date Test5
#[test]
fn pkits_4_2_5_invalid_ca_notafter_date_test5() {
    let expected_date = validity_date(2011, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid CA notAfter Date Test5 EE")
        .crls(&["Bad notAfter Date CA CRL"])
        .certs(&["Bad notAfter Date CA Cert"])
        .invalid(
            Some(1),
            ValidatorReason::Expired,
            &format!("Could not validate certificate: certificate expired on {expected_date}"),
        );
}

// 4.2.6 Invalid EE notAfter Date Test6
#[test]
fn pkits_4_2_6_invalid_ee_notafter_date_test6() {
    let expected_date = validity_date(2011, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid EE notAfter Date Test6 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Expired,
            &format!("Could not validate certificate: certificate expired on {expected_date}"),
        );
}

// 4.2.7 Invalid pre2000 UTC EE notAfter Date Test7
#[test]
fn pkits_4_2_7_invalid_pre2000_utc_ee_notafter_date_test7() {
    let expected_date = validity_date(1999, 1, 1, 12, 1, 0);
    Pkits::new()
        .end_entity("Invalid pre2000 UTC EE notAfter Date Test7 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Expired,
            &format!("Could not validate certificate: certificate expired on {expected_date}"),
        );
}

// 4.2.8 Valid GeneralizedTime notAfter Date Test8
#[test]
fn pkits_4_2_8_valid_generalizedtime_notafter_date_test8() {
    Pkits::new()
        .end_entity("Valid GeneralizedTime notAfter Date Test8 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .valid();
}

// 4.3.1 Invalid Name Chaining EE Test1
#[test]
fn pkits_4_3_1_invalid_name_chaining_ee_test1() {
    Pkits::new()
        .end_entity("Invalid Name Chaining Test1 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .invalid_prefix(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "No CRLs found for issuer ",
        );
}

// 4.3.2 Invalid Name Chaining Order Test2
#[test]
fn pkits_4_3_2_invalid_name_chaining_order_test2() {
    Pkits::new()
        .end_entity("Invalid Name Chaining Order Test2 EE")
        .crls(&["Name Order CA CRL"])
        .certs(&["Name Ordering CA Cert"])
        .invalid_prefix(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "No CRLs found for issuer ",
        );
}

// 4.3.3 Valid Name Chaining Whitespace Test3
#[test]
fn pkits_4_3_3_valid_name_chaining_whitespace_test3() {
    Pkits::new()
        .end_entity("Valid Name Chaining Whitespace Test3 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .valid();
}

// 4.3.4 Valid Name Chaining Whitespace Test4
#[test]
fn pkits_4_3_4_valid_name_chaining_whitespace_test4() {
    Pkits::new()
        .end_entity("Valid Name Chaining Whitespace Test4 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .valid();
}

// 4.3.5 Valid Name Chaining Capitalization Test5
#[test]
fn pkits_4_3_5_valid_name_chaining_capitalization_test5() {
    Pkits::new()
        .end_entity("Valid Name Chaining Capitalization Test5 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .valid();
}

// 4.3.6 Valid Name Chaining UIDs Test6
#[test]
fn pkits_4_3_6_valid_name_chaining_uids_test6() {
    Pkits::new()
        .end_entity("Valid Name UIDs Test6 EE")
        .crls(&["UID CA CRL"])
        .certs(&["UID CA Cert"])
        .valid();
}

// 4.3.7 Valid RFC3280 Mandatory Attribute Types Test7
#[test]
fn pkits_4_3_7_valid_rfc3280_mandatory_attribute_types_test7() {
    Pkits::new()
        .end_entity("Valid RFC3280 Mandatory Attribute Types Test7 EE")
        .crls(&["RFC3280 Mandatory AttributeTypes CA CRL"])
        .certs(&["RFC3280 Mandatory Attribute Types CA Cert"])
        .valid();
}

// 4.3.8 Valid RFC3280 Optional Attribute Types Test8
#[test]
fn pkits_4_3_8_valid_rfc3280_optional_attribute_types_test8() {
    Pkits::new()
        .end_entity("Valid RFC3280 Optional Attribute Types Test8 EE")
        .crls(&["RFC3280 Optional AttributeTypes CA CRL"])
        .certs(&["RFC3280 Optional Attribute Types CA Cert"])
        .valid();
}

// 4.3.9 Valid UTF8String Encoded Names Test9
#[test]
fn pkits_4_3_9_valid_utf8string_encoded_names_test9() {
    Pkits::new()
        .end_entity("Valid UTF8String Encoded Names Test9 EE")
        .crls(&["UTF8String Encoded Names CA CRL"])
        .certs(&["UTF8String Encoded Names CA Cert"])
        .valid();
}

// 4.3.10 Valid Rollover from PrintableString to UTF8String Test10
#[test]
fn pkits_4_3_10_valid_rollover_from_printablestring_to_utf8string_test10() {
    Pkits::new()
        .end_entity("Valid Rollover from PrintableString to UTF8String Test10 EE")
        .crls(&["Rollover fromPrintableString to UTF8String CA CRL"])
        .certs(&["Rollover from PrintableString to UTF8String CA Cert"])
        .valid();
}

// 4.3.11 Valid UTF8String Case Insensitive Match Test11
#[test]
fn pkits_4_3_11_valid_utf8string_case_insensitive_match_test11() {
    Pkits::new()
        .end_entity("Valid UTF8String Case Insensitive Match Test11 EE")
        .crls(&["UTF8String Case InsensitiveMatch CA CRL"])
        .certs(&["UTF8String Case Insensitive Match CA Cert"])
        .valid();
}

// 4.4.1 Missing CRL Test1
#[test]
fn pkits_4_4_1_missing_crl_test1() {
    Pkits::new()
        .end_entity("Invalid Missing CRL Test1 EE")
        .certs(&["No CRL CA Cert"])
        .invalid_prefix(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "No CRLs found for issuer ",
        );
}

// 4.4.2 Invalid Revoked CA Test2
#[test]
fn pkits_4_4_2_invalid_revoked_ca_test2() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid Revoked CA Test2 EE")
        .crls(&["Revoked subCA CRL", "Good CA CRL"])
        .certs(&["Revoked subCA Cert", "Good CA Cert"])
        .invalid(
            Some(1),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.4.3 Invalid Revoked EE Test3
#[test]
fn pkits_4_4_3_invalid_revoked_ee_test3() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 1);
    Pkits::new()
        .end_entity("Invalid Revoked EE Test3 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.4.4 Invalid Bad CRL Signature Test4
#[test]
fn pkits_4_4_4_invalid_bad_crl_signature_test4() {
    Pkits::new()
        .end_entity("Invalid Bad CRL Signature Test4 EE")
        .crls(&["Bad CRL Signature CA CRL"])
        .certs(&["Bad CRL Signature CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "Cannot verify CRL.",
        );
}

// 4.4.5 Invalid Bad CRL Issuer Name Test5
#[test]
fn pkits_4_4_5_invalid_bad_crl_issuer_name_test5() {
    Pkits::new()
        .end_entity("Invalid Bad CRL Issuer Name Test5 EE")
        .crls(&["Bad CRL Issuer Name CA CRL"])
        .certs(&["Bad CRL Issuer Name CA Cert"])
        .invalid_prefix(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "No CRLs found for issuer ",
        );
}

// 4.4.6 Invalid Wrong CRL Test6
#[test]
fn pkits_4_4_6_invalid_wrong_crl_test6() {
    Pkits::new()
        .end_entity("Invalid Wrong CRL Test6 EE")
        .crls(&["Wrong CRL CA CRL"])
        .certs(&["Wrong CRL CA Cert"])
        .invalid_prefix(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "No CRLs found for issuer ",
        );
}

// 4.4.7 Valid Two CRLs Test7
#[test]
fn pkits_4_4_7_valid_two_crls_test7() {
    Pkits::new()
        .end_entity("Valid Two CRLs Test7 EE")
        .crls(&["Two CRLs CA Bad CRL", "Two CRLs CA Good CRL"])
        .certs(&["Two CRLs CA Cert"])
        .valid();
}

// 4.4.8 Invalid Unknown CRL Entry Extension Test8
#[test]
fn pkits_4_4_8_invalid_unknown_crl_entry_extension_test8() {
    Pkits::new()
        .end_entity("Invalid Unknown CRL Entry Extension Test8 EE")
        .crls(&["Unknown CRL Entry Extension CACRL"])
        .certs(&["Unknown CRL Entry Extension CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "CRL entry has unsupported critical extensions.",
        );
}

// 4.4.9 Invalid Unknown CRL Extension Test9
#[test]
fn pkits_4_4_9_invalid_unknown_crl_extension_test9() {
    Pkits::new()
        .end_entity("Invalid Unknown CRL Extension Test9 EE")
        .crls(&["Unknown CRL Extension CA CRL"])
        .certs(&["Unknown CRL Extension CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "CRL contains unsupported critical extensions.",
        );
}

// 4.4.10 Invalid Unknown CRL Extension Test10
#[test]
fn pkits_4_4_10_invalid_unknown_crl_extension_test10() {
    Pkits::new()
        .end_entity("Invalid Unknown CRL Extension Test10 EE")
        .crls(&["Unknown CRL Extension CA CRL"])
        .certs(&["Unknown CRL Extension CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "CRL contains unsupported critical extensions.",
        );
}

// 4.4.11 Invalid Old CRL nextUpdate Test11
#[test]
fn pkits_4_4_11_invalid_old_crl_nextupdate_test11() {
    Pkits::new()
        .end_entity("Invalid Old CRL nextUpdate Test11 EE")
        .crls(&["Old CRL nextUpdate CA CRL"])
        .certs(&["Old CRL nextUpdate CA Cert"])
        .invalid_prefix(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "No CRLs found for issuer ",
        );
}

// 4.4.12 Invalid pre2000 CRL nextUpdate Test12
#[test]
fn pkits_4_4_12_invalid_pre2000_crl_nextupdate_test12() {
    Pkits::new()
        .end_entity("Invalid pre2000 CRL nextUpdate Test12 EE")
        .crls(&["pre2000 CRL nextUpdate CA CRL"])
        .certs(&["pre2000 CRL nextUpdate CA Cert"])
        .invalid_prefix(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "No CRLs found for issuer ",
        );
}

// 4.4.13 Valid GeneralizedTime CRL nextUpdate Test13
#[test]
fn pkits_4_4_13_valid_generalizedtime_crl_nextupdate_test13() {
    Pkits::new()
        .end_entity("Valid GeneralizedTime CRL nextUpdate Test13 EE")
        .crls(&["GeneralizedTime CRL nextUpdateCA CRL"])
        .certs(&["GeneralizedTime CRL nextUpdate CA Cert"])
        .valid();
}

// 4.4.14 Valid Negative Serial Number Test14
#[test]
fn pkits_4_4_14_valid_negative_serial_number_test14() {
    Pkits::new()
        .end_entity("Valid Negative Serial Number Test14 EE")
        .crls(&["Negative Serial Number CA CRL"])
        .certs(&["Negative Serial Number CA Cert"])
        .valid();
}

// 4.4.15 Invalid Negative Serial Number Test15
#[test]
fn pkits_4_4_15_invalid_negative_serial_number_test15() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid Negative Serial Number Test15 EE")
        .crls(&["Negative Serial Number CA CRL"])
        .certs(&["Negative Serial Number CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.4.16 Valid Long Serial Number Test16
#[test]
fn pkits_4_4_16_valid_long_serial_number_test16() {
    Pkits::new()
        .end_entity("Valid Long Serial Number Test16 EE")
        .crls(&["Long Serial Number CA CRL"])
        .certs(&["Long Serial Number CA Cert"])
        .valid();
}

// 4.4.17 Valid Long Serial Number Test17
#[test]
fn pkits_4_4_17_valid_long_serial_number_test17() {
    Pkits::new()
        .end_entity("Valid Long Serial Number Test17 EE")
        .crls(&["Long Serial Number CA CRL"])
        .certs(&["Long Serial Number CA Cert"])
        .valid();
}

// 4.4.18 Invalid Long Serial Number Test18
#[test]
fn pkits_4_4_18_invalid_long_serial_number_test18() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid Long Serial Number Test18 EE")
        .crls(&["Long Serial Number CA CRL"])
        .certs(&["Long Serial Number CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.4.19 Valid Separate Certificate and CRL Keys Test19
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK -- 'Trust anchor for certification path not found.'"]
fn pkits_4_4_19_valid_separate_certificate_and_crl_keys_test19() {
    Pkits::new()
        .end_entity("Valid Separate Certificate and CRL Keys Test19 EE")
        .crls(&["Separate Certificate and CRLKeys CRL"])
        .certs(&[
            "SeparateCertificate and CRL Keys CRL Signing Cert",
            "Separate Certificate and CRL Keys Certificate Signing CA Cert",
        ])
        .valid();
}

// 4.4.20 Invalid Separate Certificate and CRL Keys Test20
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK getting 'Trust anchor for certification path not found.'"]
fn pkits_4_4_20_invalid_separate_certificate_and_crl_keys_test20() {
    Pkits::new()
        .end_entity("Invalid Separate Certificate and CRL Keys Test20 EE")
        .crls(&["Separate Certificate and CRLKeys CRL"])
        .certs(&[
            "SeparateCertificate and CRL Keys CRL Signing Cert",
            "Separate Certificate and CRL Keys Certificate Signing CA Cert",
        ])
        .invalid(Some(1), ValidatorReason::Revoked, "--");
}

// 4.4.21 Invalid Separate Certificate and CRL Keys Test21
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK -- Got: Trust anchor for certification path not found."]
fn pkits_4_4_21_invalid_separate_certificate_and_crl_keys_test21() {
    Pkits::new()
        .end_entity("Invalid Separate Certificate and CRL Keys Test21 EE")
        .crls(&["Separate Certificate and CRLKeys CA2 CRL"])
        .certs(&[
            "SeparateCertificate and CRL Keys CA2 CRL Signing Cert",
            "Separate Certificate and CRL Keys CA2 Certificate Signing CA Cert",
        ])
        .invalid(Some(1), ValidatorReason::UndeterminedRevocationStatus, "--");
}

// 4.5.1 Valid Basic Self-Issued Old With New Test1
#[test]
fn pkits_4_5_1_valid_basic_self_issued_old_with_new_test1() {
    Pkits::new()
        .end_entity("Valid Basic SelfIssued Old With New Test1 EE")
        .certs(&[
            "Basic SelfIssued New Key OldWithNew CA Cert",
            "Basic SelfIssued New Key CA Cert",
        ])
        .crls(&["Basic SelfIssued New Key CA CRL"])
        .valid();
}

// 4.5.2 Invalid Basic Self-Issued Old With New Test2
#[test]
fn pkits_4_5_2_invalid_basic_self_issued_old_with_new_test2() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid Basic SelfIssued Old With New Test2 EE")
        .certs(&[
            "Basic SelfIssued New Key OldWithNew CA Cert",
            "Basic SelfIssued New Key CA Cert",
        ])
        .crls(&["Basic SelfIssued New Key CA CRL"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.5.3 Valid Basic Self-Issued New With Old Test3
#[test]
fn pkits_4_5_3_valid_basic_self_issued_new_with_old_test3() {
    Pkits::new()
        .end_entity("Valid Basic SelfIssued New With Old Test3 EE")
        .crls(&[
            "Basic SelfIssued Old Key CACRL",
            "Basic SelfIssued Old Key SelfIssued CertCRL",
        ])
        .certs(&[
            "Basic SelfIssued Old Key NewWithOld CA Cert",
            "Basic SelfIssued Old Key CA Cert",
        ])
        .valid();
}

// 4.5.4 Valid Basic Self-Issued New With Old Test4
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK I think it is not using the new-signed-with-old"]
fn pkits_4_5_4_valid_basic_self_issued_new_with_old_test4() {
    Pkits::new()
        .end_entity("Valid Basic SelfIssued New With Old Test4 EE")
        .crls(&[
            "Basic SelfIssued Old Key CACRL",
            "Basic SelfIssued Old Key SelfIssued CertCRL",
        ])
        .certs(&[
            "Basic SelfIssued Old Key NewWithOld CA Cert",
            "Basic SelfIssued Old Key CA Cert",
        ])
        .valid();
}

// 4.5.5 Invalid Basic Self-Issued New With Old Test5
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK I think it is not using the new-signed-with-old"]
fn pkits_4_5_5_invalid_basic_self_issued_new_with_old_test5() {
    Pkits::new()
        .end_entity("Invalid Basic SelfIssued New With Old Test5 EE")
        .crls(&[
            "Basic SelfIssued Old Key CACRL",
            "Basic SelfIssued Old Key SelfIssued CertCRL",
        ])
        .certs(&[
            "Basic SelfIssued Old Key NewWithOld CA Cert",
            "Basic SelfIssued Old Key CA Cert",
        ])
        .invalid(Some(0), ValidatorReason::Revoked, "--");
}

// 4.5.6 Valid Basic Self-Issued CRL Signing Key Test6
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK we may be too strict here, 'Intermediate certificate lacks BasicConstraints'"]
fn pkits_4_5_6_valid_basic_self_issued_crl_signing_key_test6() {
    Pkits::new()
        .end_entity("Valid Basic SelfIssued CRL Signing Key Test6 EE")
        .crls(&["Basic SelfIssued CRL SigningKey CA CRL"])
        .certs(&["Basic SelfIssued CRL Signing Key CRL Cert"])
        .crls(&["Basic SelfIssued CRL SigningKey CRL Cert CRL"])
        .certs(&["Basic SelfIssued CRL Signing Key CA Cert"])
        .valid();
}

// 4.5.7 Invalid Basic Self-Issued CRL Signing Key Test7
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK we may be too strict here, 'Intermediate certificate lacks BasicConstraints'"]
fn pkits_4_5_7_invalid_basic_self_issued_crl_signing_key_test7() {
    Pkits::new()
        .end_entity("Invalid Basic SelfIssued CRL Signing Key Test7 EE")
        .crls(&[
            "Basic SelfIssued CRL SigningKey CA CRL",
            "Basic SelfIssued CRL SigningKey CRL Cert CRL",
        ])
        .certs(&[
            "Basic SelfIssued CRL Signing Key CRL Cert",
            "Basic SelfIssued CRL Signing Key CA Cert",
        ])
        .invalid(Some(1), ValidatorReason::Revoked, "--");
}

// 4.5.8 Invalid Basic Self-Issued CRL Signing Key Test7
#[test]
fn pkits_4_5_8_invalid_basic_self_issued_crl_signing_key_test7() {
    Pkits::new()
        .end_entity("Invalid Basic SelfIssued CRL Signing Key Test8 EE")
        .crls(&["Basic SelfIssued CRL SigningKey CA CRL"])
        .certs(&["Basic SelfIssued CRL Signing Key CRL Cert"])
        .crls(&["Basic SelfIssued CRL SigningKey CRL Cert CRL"])
        .certs(&["Basic SelfIssued CRL Signing Key CA Cert"])
        .invalid(
            Some(1),
            ValidatorReason::NotCaCertificate,
            "Intermediate certificate lacks BasicConstraints",
        );
}

// 4.6.1 Invalid Missing basicConstraints Test1
#[test]
fn pkits_4_6_1_invalid_missing_basicconstraints_test1() {
    Pkits::new()
        .end_entity("Invalid Missing basicConstraints Test1 EE")
        .crls(&["Missing basicConstraints CA CRL"])
        .certs(&["Missing basicConstraints CA Cert"])
        .invalid(
            Some(1),
            ValidatorReason::NotCaCertificate,
            "Intermediate certificate lacks BasicConstraints",
        );
}

// 4.6.2 Invalid cA False Test2
#[test]
fn pkits_4_6_2_invalid_ca_false_test2() {
    Pkits::new()
        .end_entity("Invalid cA False Test2 EE")
        .crls(&["basicConstraints Critical cA FalseCA CRL"])
        .certs(&["basicConstraints Critical cA False CA Cert"])
        .invalid(
            Some(1),
            ValidatorReason::NotCaCertificate,
            "Not a CA certificate",
        );
}

// 4.6.3 Invalid cA False Test3
#[test]
fn pkits_4_6_3_invalid_ca_false_test3() {
    Pkits::new()
        .end_entity("Invalid cA False Test3 EE")
        .crls(&["basicConstraints Not CriticalcA False CA CRL"])
        .certs(&["basicConstraints Not Critical cA False CA Cert"])
        .invalid(
            Some(1),
            ValidatorReason::NotCaCertificate,
            "Not a CA certificate",
        );
}

// 4.6.4 Valid basicConstraints Not Critical Test4
#[test]
fn pkits_4_6_4_valid_basicconstraints_not_critical_test4() {
    Pkits::new()
        .end_entity("Valid basicConstraints Not Critical Test4 EE")
        .crls(&["basicConstraints Not Critical CA CRL"])
        .certs(&["basicConstraints Not Critical CA Cert"])
        .valid();
}

// 4.6.5 Invalid pathLenConstraint Test5
#[test]
fn pkits_4_6_5_invalid_pathlenconstraint_test5() {
    Pkits::new()
        .end_entity("Invalid pathLenConstraint Test5 EE")
        .crls(&["pathLenConstraint0 subCA CRL", "pathLenConstraint0 CA CRL"])
        .certs(&[
            "pathLenConstraint0 subCA Cert",
            "pathLenConstraint0 CA Cert",
        ])
        .invalid(
            Some(1),
            ValidatorReason::PathTooLong,
            "Max path length not greater than zero",
        );
}

// 4.6.6 Invalid pathLenConstraint Test6
#[test]
fn pkits_4_6_6_invalid_pathlenconstraint_test6() {
    Pkits::new()
        .end_entity("Invalid pathLenConstraint Test6 EE")
        .crls(&["pathLenConstraint0 subCA CRL", "pathLenConstraint0 CA CRL"])
        .certs(&[
            "pathLenConstraint0 subCA Cert",
            "pathLenConstraint0 CA Cert",
        ])
        .invalid(
            Some(1),
            ValidatorReason::PathTooLong,
            "Max path length not greater than zero",
        );
}

// 4.6.7 Valid pathLenConstraint Test7
#[test]
fn pkits_4_6_7_valid_pathlenconstraint_test7() {
    Pkits::new()
        .end_entity("Valid pathLenConstraint Test7 EE")
        .crls(&["pathLenConstraint0 CA CRL"])
        .certs(&["pathLenConstraint0 CA Cert"])
        .valid();
}

// 4.6.8 Valid pathLenConstraint Test8
#[test]
fn pkits_4_6_8_valid_pathlenconstraint_test8() {
    Pkits::new()
        .end_entity("Valid pathLenConstraint Test8 EE")
        .crls(&["pathLenConstraint0 CA CRL"])
        .certs(&["pathLenConstraint0 CA Cert"])
        .valid();
}

// 4.6.9 Invalid pathLenConstraint Test9
#[test]
fn pkits_4_6_9_invalid_pathlenconstraint_test9() {
    Pkits::new()
        .end_entity("Invalid pathLenConstraint Test9 EE")
        .crls(&[
            "pathLenConstraint6 subsubCA00 CRL",
            "pathLenConstraint6 subCA0 CRL",
            "pathLenConstraint6 CA CRL",
        ])
        .certs(&[
            "pathLenConstraint6 subsubCA00 Cert",
            "pathLenConstraint6 subCA0 Cert",
            "pathLenConstraint6 CA Cert",
        ])
        .invalid(
            Some(1),
            ValidatorReason::PathTooLong,
            "Max path length not greater than zero",
        );
}

// 4.6.10 Invalid pathLenConstraint Test10
#[test]
fn pkits_4_6_10_invalid_pathlenconstraint_test10() {
    Pkits::new()
        .end_entity("Invalid pathLenConstraint Test10 EE")
        .crls(&[
            "pathLenConstraint6 subsubCA00 CRL",
            "pathLenConstraint6 subCA0 CRL",
            "pathLenConstraint6 CA CRL",
        ])
        .certs(&[
            "pathLenConstraint6 subsubCA00 Cert",
            "pathLenConstraint6 subCA0 Cert",
            "pathLenConstraint6 CA Cert",
        ])
        .invalid(
            Some(1),
            ValidatorReason::PathTooLong,
            "Max path length not greater than zero",
        );
}

// 4.6.11 Invalid pathLenConstraint Test11
#[test]
fn pkits_4_6_11_invalid_pathlenconstraint_test11() {
    Pkits::new()
        .end_entity("Invalid pathLenConstraint Test11 EE")
        .crls(&[
            "pathLenConstraint6subsubsubCA11X CRL",
            "pathLenConstraint6 subsubCA11 CRL",
            "pathLenConstraint6 subCA1 CRL",
            "pathLenConstraint6 CA CRL",
        ])
        .certs(&[
            "pathLenConstraint6 subsubsubCA11X Cert",
            "pathLenConstraint6 subsubCA11 Cert",
            "pathLenConstraint6 subCA1 Cert",
            "pathLenConstraint6 CA Cert",
        ])
        .invalid(
            Some(1),
            ValidatorReason::PathTooLong,
            "Max path length not greater than zero",
        );
}

// 4.6.12 Invalid pathLenConstraint Test12
#[test]
fn pkits_4_6_12_invalid_pathlenconstraint_test12() {
    Pkits::new()
        .end_entity("Invalid pathLenConstraint Test12 EE")
        .crls(&[
            "pathLenConstraint6subsubsubCA11X CRL",
            "pathLenConstraint6 subsubCA11 CRL",
            "pathLenConstraint6 subCA1 CRL",
            "pathLenConstraint6 CA CRL",
        ])
        .certs(&[
            "pathLenConstraint6 subsubsubCA11X Cert",
            "pathLenConstraint6 subsubCA11 Cert",
            "pathLenConstraint6 subCA1 Cert",
            "pathLenConstraint6 CA Cert",
        ])
        .invalid(
            Some(1),
            ValidatorReason::PathTooLong,
            "Max path length not greater than zero",
        );
}

// 4.6.13 Valid pathLenConstraint Test13
#[test]
fn pkits_4_6_13_valid_pathlenconstraint_test13() {
    Pkits::new()
        .end_entity("Valid pathLenConstraint Test13 EE")
        .crls(&[
            "pathLenConstraint6subsubsubCA41X CRL",
            "pathLenConstraint6 subsubCA41 CRL",
            "pathLenConstraint6 subCA4 CRL",
            "pathLenConstraint6 CA CRL",
        ])
        .certs(&[
            "pathLenConstraint6 subsubsubCA41X Cert",
            "pathLenConstraint6 subsubCA41 Cert",
            "pathLenConstraint6 subCA4 Cert",
            "pathLenConstraint6 CA Cert",
        ])
        .valid();
}

// 4.6.14 Valid pathLenConstraint Test14
#[test]
fn pkits_4_6_14_valid_pathlenconstraint_test14() {
    Pkits::new()
        .end_entity("Valid pathLenConstraint Test14 EE")
        .crls(&[
            "pathLenConstraint6subsubsubCA41X CRL",
            "pathLenConstraint6 subsubCA41 CRL",
            "pathLenConstraint6 subCA4 CRL",
            "pathLenConstraint6 CA CRL",
        ])
        .certs(&[
            "pathLenConstraint6 subsubsubCA41X Cert",
            "pathLenConstraint6 subsubCA41 Cert",
            "pathLenConstraint6 subCA4 Cert",
            "pathLenConstraint6 CA Cert",
        ])
        .valid();
}

// 4.6.15 Valid Self-Issued pathLenConstraint Test15
#[test]
fn pkits_4_6_15_valid_self_issued_pathlenconstraint_test15() {
    Pkits::new()
        .end_entity("Valid SelfIssued pathLenConstraint Test15 EE")
        .certs(&[
            "pathLenConstraint0 SelfIssued CA Cert",
            "pathLenConstraint0 CA Cert",
        ])
        .crls(&["pathLenConstraint0 CA CRL"])
        .valid();
}

// 4.6.16 Invalid Self-Issued pathLenConstraint Test16
#[test]
fn pkits_4_6_16_invalid_self_issued_pathlenconstraint_test16() {
    Pkits::new()
        .end_entity("Invalid SelfIssued pathLenConstraint Test16 EE")
        .crls(&["pathLenConstraint0 subCA2 CRL", "pathLenConstraint0 CA CRL"])
        .certs(&[
            "pathLenConstraint0 subCA2 Cert",
            "pathLenConstraint0 SelfIssued CA Cert",
            "pathLenConstraint0 CA Cert",
        ])
        .invalid(
            Some(1),
            ValidatorReason::PathTooLong,
            "Max path length not greater than zero",
        );
}

// 4.6.17 Valid Self-Issued pathLenConstraint Test17
#[test]
fn pkits_4_6_17_valid_self_issued_pathlenconstraint_test17() {
    Pkits::new()
        .end_entity("Valid SelfIssued pathLenConstraint Test17 EE")
        .certs(&[
            "pathLenConstraint1 SelfIssued subCA Cert",
            "pathLenConstraint1 subCA Cert",
            "pathLenConstraint1 SelfIssued CA Cert",
            "pathLenConstraint1 CA Cert",
        ])
        .crls(&["pathLenConstraint1 subCA CRL", "pathLenConstraint1 CA CRL"])
        .valid();
}

// 4.7.1 Invalid keyUsage Critical keyCertSign False Test1
#[test]
fn pkits_4_7_1_invalid_keyusage_critical_keycertsign_false_test1() {
    Pkits::new()
        .end_entity("Invalid keyUsage Critical keyCertSign False Test1 EE")
        .crls(&["keyUsage Critical keyCertSignFalse CA CRL"])
        .certs(&["keyUsage Critical keyCertSign False CA Cert"])
        .invalid(
            Some(1),
            ValidatorReason::InvalidKeyUsage,
            "Issuer certificate keyusage extension is critical and does not permit key signing.",
        );
}

// 4.7.2 Invalid keyUsage Not Critical keyCertSign False Test2
#[test]
fn pkits_4_7_2_invalid_keyusage_not_critical_keycertsign_false_test2() {
    Pkits::new()
        .end_entity("Invalid keyUsage Not Critical keyCertSign False Test2 EE")
        .crls(&["keyUsage Not CriticalkeyCertSign False CA CRL"])
        .certs(&["keyUsage Not Critical keyCertSign False CA Cert"])
        .invalid(
            Some(1),
            ValidatorReason::InvalidKeyUsage,
            "Issuer certificate keyusage extension is critical and does not permit key signing.",
        );
}

// 4.7.3 Valid keyUsage Not Critical Test3
#[test]
fn pkits_4_7_3_valid_keyusage_not_critical_test3() {
    Pkits::new()
        .end_entity("Valid keyUsage Not Critical Test3 EE")
        .crls(&["keyUsage Not Critical CA CRL"])
        .certs(&["keyUsage Not Critical CA Cert"])
        .valid();
}

// 4.7.4 Invalid keyUsage Critical cRLSign False Test4
#[test]
fn pkits_4_7_4_invalid_keyusage_critical_crlsign_false_test4() {
    Pkits::new()
        .end_entity("Invalid keyUsage Critical cRLSign False Test4 EE")
        .crls(&["keyUsage Critical cRLSign False CACRL"])
        .certs(&["keyUsage Critical cRLSign False CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "Issuer certificate key usage extension does not permit CRL signing.",
        );
}

// 4.7.5 Invalid keyUsage Not Critical cRLSign False Test5
#[test]
fn pkits_4_7_5_invalid_keyusage_not_critical_crlsign_false_test5() {
    Pkits::new()
        .end_entity("Invalid keyUsage Not Critical cRLSign False Test5 EE")
        .crls(&["keyUsage Not Critical cRLSignFalse CA CRL"])
        .certs(&["keyUsage Not Critical cRLSign False CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "Issuer certificate key usage extension does not permit CRL signing.",
        );
}

// 4.8.1 All Certificates Same Policy Test1
#[test]
fn pkits_4_8_1_all_certificates_same_policy_test1() {
    Pkits::new()
        .end_entity("Valid Certificate Path Test1 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .explicit_policy_required(true)
        .valid();

    Pkits::new()
        .end_entity("Valid Certificate Path Test1 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .explicit_policy_required(true)
        .policies(&["NIST-test-policy-1"])
        .valid();

    Pkits::new()
        .end_entity("Valid Certificate Path Test1 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .explicit_policy_required(true)
        .policies(&["NIST-test-policy-2"])
        .invalid(
            None,
            ValidatorReason::InvalidPolicy,
            "Path processing failed on policy.",
        );

    Pkits::new()
        .end_entity("Valid Certificate Path Test1 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .explicit_policy_required(true)
        .policies(&["NIST-test-policy-1", "NIST-test-policy-2"])
        .valid();
}

// 4.8.2 All Certificates No Policies Test2
#[test]
fn pkits_4_8_2_all_certificates_no_policies_test2() {
    Pkits::new()
        .end_entity("All Certificates No Policies Test2 EE")
        .crls(&["No Policies CA CRL"])
        .certs(&["No Policies CA Cert"])
        .valid();

    Pkits::new()
        .end_entity("All Certificates No Policies Test2 EE")
        .crls(&["No Policies CA CRL"])
        .certs(&["No Policies CA Cert"])
        .explicit_policy_required(true)
        .invalid(
            Some(1),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.8.3 Different Policies Test3
#[test]
fn pkits_4_8_3_different_policies_test3() {
    Pkits::new()
        .end_entity("Different Policies Test3 EE")
        .crls(&["Policies P2 subCA CRL", "Good CA CRL"])
        .certs(&["Policies P2 subCA Cert", "Good CA Cert"])
        .valid();

    Pkits::new()
        .end_entity("Different Policies Test3 EE")
        .crls(&["Policies P2 subCA CRL", "Good CA CRL"])
        .certs(&["Policies P2 subCA Cert", "Good CA Cert"])
        .explicit_policy_required(true)
        .invalid(
            Some(1),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );

    Pkits::new()
        .end_entity("Different Policies Test3 EE")
        .crls(&["Policies P2 subCA CRL", "Good CA CRL"])
        .certs(&["Policies P2 subCA Cert", "Good CA Cert"])
        .explicit_policy_required(true)
        .policies(&["NIST-test-policy-1", "NIST-test-policy-2"])
        .invalid(
            Some(1),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.8.4 Different Policies Test4
#[test]
fn pkits_4_8_4_different_policies_test4() {
    Pkits::new()
        .end_entity("Different Policies Test4 EE")
        .crls(&["Good subCA CRL", "Good CA CRL"])
        .certs(&["Good subCA Cert", "Good CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.8.5 Different Policies Test5
#[test]
fn pkits_4_8_5_different_policies_test5() {
    Pkits::new()
        .end_entity("Different Policies Test5 EE")
        .crls(&["Policies P2 subCA2 CRL", "Good CA CRL"])
        .certs(&["Policies P2 subCA2 Cert", "Good CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.8.6 Overlapping Policies Test6
#[test]
fn pkits_4_8_6_overlapping_policies_test6() {
    Pkits::new()
        .end_entity("Overlapping Policies Test6 EE")
        .crls(&[
            "Policies P1234 subsubCAP123P12CRL",
            "Policies P1234 subCAP123 CRL",
            "Policies P1234 CA CRL",
        ])
        .certs(&[
            "Policies P1234 subsubCAP123P12 Cert",
            "Policies P1234 subCAP123 Cert",
            "Policies P1234 CA Cert",
        ])
        .valid();

    Pkits::new()
        .end_entity("Overlapping Policies Test6 EE")
        .crls(&[
            "Policies P1234 subsubCAP123P12CRL",
            "Policies P1234 subCAP123 CRL",
            "Policies P1234 CA CRL",
        ])
        .certs(&[
            "Policies P1234 subsubCAP123P12 Cert",
            "Policies P1234 subCAP123 Cert",
            "Policies P1234 CA Cert",
        ])
        .policies(&["NIST-test-policy-1"])
        .valid();

    Pkits::new()
        .end_entity("Overlapping Policies Test6 EE")
        .crls(&[
            "Policies P1234 subsubCAP123P12CRL",
            "Policies P1234 subCAP123 CRL",
            "Policies P1234 CA CRL",
        ])
        .certs(&[
            "Policies P1234 subsubCAP123P12 Cert",
            "Policies P1234 subCAP123 Cert",
            "Policies P1234 CA Cert",
        ])
        .policies(&["NIST-test-policy-2"])
        .invalid(
            None,
            ValidatorReason::InvalidPolicy,
            "Path processing failed on policy.",
        );
}

// 4.8.7 Different Policies Test7
#[test]
fn pkits_4_8_7_different_policies_test7() {
    Pkits::new()
        .end_entity("Different Policies Test7 EE")
        .crls(&[
            "Policies P123 subsubCAP12P1 CRL",
            "Policies P123 subCAP12 CRL",
            "Policies P123 CA CRL",
        ])
        .certs(&[
            "Policies P123 subsubCAP12P1 Cert",
            "Policies P123 subCAP12 Cert",
            "Policies P123 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.8.8 Different Policies Test8
#[test]
fn pkits_4_8_8_different_policies_test8() {
    Pkits::new()
        .end_entity("Different Policies Test8 EE")
        .crls(&[
            "Policies P12 subsubCAP1P2 CRL",
            "Policies P12 subCAP1 CRL",
            "Policies P12 CA CRL",
        ])
        .certs(&[
            "Policies P12 subsubCAP1P2 Cert",
            "Policies P12 subCAP1 Cert",
            "Policies P12 CA Cert",
        ])
        .invalid(
            Some(1),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.8.9 Different Policies Test9
#[test]
fn pkits_4_8_9_different_policies_test9() {
    Pkits::new()
        .end_entity("Different Policies Test9 EE")
        .crls(&[
            "Policies P123subsubsubCAP12P2P1 CRL",
            "Policies P123 subsubCAP2P2 CRL",
            "Policies P123 subCAP12 CRL",
            "Policies P123 CA CRL",
        ])
        .certs(&[
            "Policies P123 subsubsubCAP12P2P1 Cert",
            "Policies P123 subsubCAP12P2 Cert",
            "Policies P123 subCAP12 Cert",
            "Policies P123 CA Cert",
        ])
        .invalid(
            Some(1),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.8.10 All Certificates Same Policies Test10
#[test]
fn pkits_4_8_10_all_certificates_same_policies_test10() {
    Pkits::new()
        .end_entity("All Certificates Same Policies Test10 EE")
        .crls(&["Policies P12 CA CRL"])
        .certs(&["Policies P12 CA Cert"])
        .valid();

    Pkits::new()
        .end_entity("All Certificates Same Policies Test10 EE")
        .crls(&["Policies P12 CA CRL"])
        .certs(&["Policies P12 CA Cert"])
        .policies(&["NIST-test-policy-1"])
        .valid();

    Pkits::new()
        .end_entity("All Certificates Same Policies Test10 EE")
        .crls(&["Policies P12 CA CRL"])
        .certs(&["Policies P12 CA Cert"])
        .policies(&["NIST-test-policy-2"])
        .valid();
}

// 4.8.11 All Certificates AnyPolicy Test11
#[test]
fn pkits_4_8_11_all_certificates_anypolicy_test11() {
    Pkits::new()
        .end_entity("All Certificates anyPolicy Test11 EE")
        .crls(&["anyPolicy CA CRL"])
        .certs(&["anyPolicy CA Cert"])
        .valid();

    Pkits::new()
        .end_entity("All Certificates anyPolicy Test11 EE")
        .crls(&["anyPolicy CA CRL"])
        .certs(&["anyPolicy CA Cert"])
        .policies(&["NIST-test-policy-1"])
        .valid();
}

// 4.8.12 Different Policies Test12
#[test]
fn pkits_4_8_12_different_policies_test12() {
    Pkits::new()
        .end_entity("Different Policies Test12 EE")
        .crls(&["Policies P3 CA CRL"])
        .certs(&["Policies P3 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.8.13 All Certificates Same Policies Test13
#[test]
fn pkits_4_8_13_all_certificates_same_policies_test13() {
    Pkits::new()
        .end_entity("All Certificates Same Policies Test13 EE")
        .crls(&["Policies P123 CA CRL"])
        .certs(&["Policies P123 CA Cert"])
        .policies(&["NIST-test-policy-1"])
        .valid();

    Pkits::new()
        .end_entity("All Certificates Same Policies Test13 EE")
        .crls(&["Policies P123 CA CRL"])
        .certs(&["Policies P123 CA Cert"])
        .policies(&["NIST-test-policy-2"])
        .valid();

    Pkits::new()
        .end_entity("All Certificates Same Policies Test13 EE")
        .crls(&["Policies P123 CA CRL"])
        .certs(&["Policies P123 CA Cert"])
        .policies(&["NIST-test-policy-3"])
        .valid();
}

// 4.8.14 AnyPolicy Test14
#[test]
fn pkits_4_8_14_anypolicy_test14() {
    Pkits::new()
        .end_entity("AnyPolicy Test14 EE")
        .crls(&["anyPolicy CA CRL"])
        .certs(&["anyPolicy CA Cert"])
        .policies(&["NIST-test-policy-1"])
        .valid();

    Pkits::new()
        .end_entity("AnyPolicy Test14 EE")
        .crls(&["anyPolicy CA CRL"])
        .certs(&["anyPolicy CA Cert"])
        .policies(&["NIST-test-policy-2"])
        .invalid(
            None,
            ValidatorReason::InvalidPolicy,
            "Path processing failed on policy.",
        );
}

// 4.8.15 User Notice Qualifier Test15
#[test]
fn pkits_4_8_15_user_notice_qualifier_test15() {
    Pkits::new()
        .end_entity("User Notice Qualifier Test15 EE")
        .valid();

    Pkits::new()
        .policies(&["NIST-test-policy-2"])
        .end_entity("User Notice Qualifier Test15 EE")
        .invalid(
            None,
            ValidatorReason::InvalidPolicy,
            "Path processing failed on policy.",
        );
}

// 4.8.16 User Notice Qualifier Test16
#[test]
fn pkits_4_8_16_user_notice_qualifier_test16() {
    Pkits::new()
        .end_entity("User Notice Qualifier Test16 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .policies(&["NIST-test-policy-1"])
        .valid();
}

// 4.8.17 User Notice Qualifier Test17
#[test]
fn pkits_4_8_17_user_notice_qualifier_test17() {
    Pkits::new()
        .end_entity("User Notice Qualifier Test17 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .policies(&["NIST-test-policy-1"])
        .valid();
}

// 4.8.18 User Notice Qualifier Test18
#[test]
fn pkits_4_8_18_user_notice_qualifier_test18() {
    Pkits::new()
        .end_entity("User Notice Qualifier Test18 EE")
        .crls(&["Policies P12 CA CRL"])
        .certs(&["Policies P12 CA Cert"])
        .policies(&["NIST-test-policy-1"])
        .valid();

    Pkits::new()
        .end_entity("User Notice Qualifier Test18 EE")
        .crls(&["Policies P12 CA CRL"])
        .certs(&["Policies P12 CA Cert"])
        .policies(&["NIST-test-policy-2"])
        .valid();
}

// 4.8.19 User Notice Qualifier Test19
#[test]
fn pkits_4_8_19_user_notice_qualifier_test19() {
    Pkits::new()
        .end_entity("User Notice Qualifier Test19 EE")
        .valid();
}

// 4.8.20 CPS Pointer Qualifier Test20
#[test]
fn pkits_4_8_20_cps_pointer_qualifier_test20() {
    Pkits::new()
        .end_entity("CPS Pointer Qualifier Test20 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert"])
        .valid();
}

// 4.9.1 Valid RequireExplicitPolicy Test1
#[test]
fn pkits_4_9_1_valid_requireexplicitpolicy_test1() {
    Pkits::new()
        .end_entity("Valid requireExplicitPolicy Test1 EE")
        .crls(&[
            "requireExplicitPolicy10subsubsubCA CRL",
            "requireExplicitPolicy10 subsubCACRL",
            "requireExplicitPolicy10 subCA CRL",
            "requireExplicitPolicy10 CA CRL",
        ])
        .certs(&[
            "requireExplicitPolicy10 subsubsubCA Cert",
            "requireExplicitPolicy10 subsubCA Cert",
            "requireExplicitPolicy10 subCA Cert",
            "requireExplicitPolicy10 CA Cert",
        ])
        .valid();
}

// 4.9.2 Valid RequireExplicitPolicy Test2
#[test]
fn pkits_4_9_2_valid_requireexplicitpolicy_test2() {
    Pkits::new()
        .end_entity("Valid requireExplicitPolicy Test2 EE")
        .crls(&[
            "requireExplicitPolicy5 subsubsubCACRL",
            "requireExplicitPolicy5 subsubCA CRL",
            "requireExplicitPolicy5 subCA CRL",
            "requireExplicitPolicy5 CA CRL",
        ])
        .certs(&[
            "requireExplicitPolicy5 subsubsubCA Cert",
            "requireExplicitPolicy5 subsubCA Cert",
            "requireExplicitPolicy5 subCA Cert",
            "requireExplicitPolicy5 CA Cert",
        ])
        .valid();
}

// 4.9.3 Invalid RequireExplicitPolicy Test3
#[test]
fn pkits_4_9_3_invalid_requireexplicitpolicy_test3() {
    Pkits::new()
        .end_entity("Invalid requireExplicitPolicy Test3 EE")
        .crls(&[
            "requireExplicitPolicy4 subsubsubCACRL",
            "requireExplicitPolicy4 subsubCA CRL",
            "requireExplicitPolicy4 subCA CRL",
            "requireExplicitPolicy4 CA CRL",
        ])
        .certs(&[
            "requireExplicitPolicy4 subsubsubCA Cert",
            "requireExplicitPolicy4 subsubCA Cert",
            "requireExplicitPolicy4 subCA Cert",
            "requireExplicitPolicy4 CA Cert",
        ])
        .invalid(
            None,
            ValidatorReason::InvalidPolicy,
            "Path processing failed on policy.",
        );
}

// 4.9.4 Valid RequireExplicitPolicy Test4
#[test]
fn pkits_4_9_4_valid_requireexplicitpolicy_test4() {
    Pkits::new()
        .end_entity("Valid requireExplicitPolicy Test4 EE")
        .crls(&[
            "requireExplicitPolicy0 subsubsubCACRL",
            "requireExplicitPolicy0 subsubCA CRL",
            "requireExplicitPolicy0 subCA CRL",
            "requireExplicitPolicy0 CA CRL",
        ])
        .certs(&[
            "requireExplicitPolicy0 subsubsubCA Cert",
            "requireExplicitPolicy0 subsubCA Cert",
            "requireExplicitPolicy0 subCA Cert",
            "requireExplicitPolicy0 CA Cert",
        ])
        .valid();
}

// 4.9.5 Invalid RequireExplicitPolicy Test5
#[test]
fn pkits_4_9_5_invalid_requireexplicitpolicy_test5() {
    Pkits::new()
        .end_entity("Invalid requireExplicitPolicy Test5 EE")
        .crls(&[
            "requireExplicitPolicy7subsubsubCARE2RE4 CRL",
            "requireExplicitPolicy7subsubCARE2RE4 CRL",
            "requireExplicitPolicy7 subCARE2 CRL",
            "requireExplicitPolicy7 CA CRL",
        ])
        .certs(&[
            "requireExplicitPolicy7 subsubsubCARE2RE4 Cert",
            "requireExplicitPolicy7 subsubCARE2RE4 Cert",
            "requireExplicitPolicy7 subCARE2 Cert",
            "requireExplicitPolicy7 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.9.6 Valid Self-Issued requireExplicitPolicy Test6
#[test]
fn pkits_4_9_6_valid_self_issued_requireexplicitpolicy_test6() {
    Pkits::new()
        .end_entity("Valid SelfIssued requireExplicitPolicy Test6 EE")
        .certs(&[
            "requireExplicitPolicy2 SelfIssued CA Cert",
            "requireExplicitPolicy2 CA Cert",
        ])
        .crls(&["requireExplicitPolicy2 CA CRL"])
        .valid();
}

// 4.9.7 Invalid Self-Issued requireExplicitPolicy Test7
#[test]
fn pkits_4_9_7_invalid_self_issued_requireexplicitpolicy_test7() {
    Pkits::new()
        .end_entity("Invalid SelfIssued requireExplicitPolicy Test7 EE")
        .crls(&[
            "requireExplicitPolicy2 subCA CRL",
            "requireExplicitPolicy2 CA CRL",
        ])
        .certs(&[
            "requireExplicitPolicy2 subCA Cert",
            "requireExplicitPolicy2 SelfIssued CA Cert",
            "requireExplicitPolicy2 CA Cert",
        ])
        .invalid(
            None,
            ValidatorReason::InvalidPolicy,
            "Path processing failed on policy.",
        );
}

// 4.9.8 Invalid Self-Issued requireExplicitPolicy Test8
#[test]
fn pkits_4_9_8_invalid_self_issued_requireexplicitpolicy_test8() {
    Pkits::new()
        .end_entity("Invalid SelfIssued requireExplicitPolicy Test8 EE")
        .certs(&[
            "requireExplicitPolicy2 SelfIssued subCA Cert",
            "requireExplicitPolicy2 subCA Cert",
            "requireExplicitPolicy2 SelfIssued CA Cert",
            "requireExplicitPolicy2 CA Cert",
        ])
        .crls(&[
            "requireExplicitPolicy2 subCA CRL",
            "requireExplicitPolicy2 CA CRL",
        ])
        .invalid(
            None,
            ValidatorReason::InvalidPolicy,
            "Path processing failed on policy.",
        );
}

// 4.10.1 Valid Policy Mapping Test1
#[test]
fn pkits_4_10_1_valid_policy_mapping_test1() {
    Pkits::new()
        .end_entity("Valid Policy Mapping Test1 EE")
        .crls(&["Mapping 1to2 CA CRL"])
        .certs(&["Mapping 1to2 CA Cert"])
        .policies(&["NIST-test-policy-1"])
        .valid();

    Pkits::new()
        .end_entity("Valid Policy Mapping Test1 EE")
        .crls(&["Mapping 1to2 CA CRL"])
        .certs(&["Mapping 1to2 CA Cert"])
        .policies(&["NIST-test-policy-2"])
        .invalid(
            None,
            ValidatorReason::InvalidPolicy,
            "Path processing failed on policy.",
        );

    Pkits::new()
        .end_entity("Valid Policy Mapping Test1 EE")
        .crls(&["Mapping 1to2 CA CRL"])
        .certs(&["Mapping 1to2 CA Cert"])
        .policy_mapping_inhibited(true)
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.10.2 Invalid Policy Mapping Test2
#[test]
fn pkits_4_10_2_invalid_policy_mapping_test2() {
    Pkits::new()
        .end_entity("Invalid Policy Mapping Test2 EE")
        .crls(&["Mapping 1to2 CA CRL"])
        .certs(&["Mapping 1to2 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );

    Pkits::new()
        .end_entity("Invalid Policy Mapping Test2 EE")
        .crls(&["Mapping 1to2 CA CRL"])
        .certs(&["Mapping 1to2 CA Cert"])
        .policy_mapping_inhibited(true)
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.10.3 Valid Policy Mapping Test3
#[test]
fn pkits_4_10_3_valid_policy_mapping_test3() {
    Pkits::new()
        .end_entity("Valid Policy Mapping Test3 EE")
        .crls(&[
            "P12 Mapping 1to3 subsubCA CRL",
            "P12 Mapping 1to3 subCA CRL",
            "P12 Mapping 1to3 CA CRL",
        ])
        .certs(&[
            "P12 Mapping 1to3 subsubCA Cert",
            "P12 Mapping 1to3 subCA Cert",
            "P12 Mapping 1to3 CA Cert",
        ])
        .policies(&["NIST-test-policy-1"])
        .invalid(
            None,
            ValidatorReason::InvalidPolicy,
            "Path processing failed on policy.",
        );

    Pkits::new()
        .end_entity("Valid Policy Mapping Test3 EE")
        .crls(&[
            "P12 Mapping 1to3 subsubCA CRL",
            "P12 Mapping 1to3 subCA CRL",
            "P12 Mapping 1to3 CA CRL",
        ])
        .certs(&[
            "P12 Mapping 1to3 subsubCA Cert",
            "P12 Mapping 1to3 subCA Cert",
            "P12 Mapping 1to3 CA Cert",
        ])
        .policies(&["NIST-test-policy-2"])
        .valid();
}

// 4.10.4 Invalid Policy Mapping Test4
#[test]
fn pkits_4_10_4_invalid_policy_mapping_test4() {
    Pkits::new()
        .end_entity("Invalid Policy Mapping Test4 EE")
        .crls(&[
            "P12 Mapping 1to3 subsubCA CRL",
            "P12 Mapping 1to3 subCA CRL",
            "P12 Mapping 1to3 CA CRL",
        ])
        .certs(&[
            "P12 Mapping 1to3 subsubCA Cert",
            "P12 Mapping 1to3 subCA Cert",
            "P12 Mapping 1to3 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.10.5 Valid Policy Mapping Test5
#[test]
fn pkits_4_10_5_valid_policy_mapping_test5() {
    Pkits::new()
        .end_entity("Valid Policy Mapping Test5 EE")
        .crls(&["P1 Mapping 1to234 subCA CRL", "P1 Mapping 1to234 CA CRL"])
        .certs(&["P1 Mapping 1to234 subCA Cert", "P1 Mapping 1to234 CA Cert"])
        .policies(&["NIST-test-policy-1"])
        .valid();

    Pkits::new()
        .end_entity("Valid Policy Mapping Test5 EE")
        .crls(&["P1 Mapping 1to234 subCA CRL", "P1 Mapping 1to234 CA CRL"])
        .certs(&["P1 Mapping 1to234 subCA Cert", "P1 Mapping 1to234 CA Cert"])
        .policies(&["NIST-test-policy-6"])
        .invalid(
            None,
            ValidatorReason::InvalidPolicy,
            "Path processing failed on policy.",
        );
}

// 4.10.6 Valid Policy Mapping Test6
#[test]
fn pkits_4_10_6_valid_policy_mapping_test6() {
    Pkits::new()
        .end_entity("Valid Policy Mapping Test6 EE")
        .crls(&["P1 Mapping 1to234 subCA CRL", "P1 Mapping 1to234 CA CRL"])
        .certs(&["P1 Mapping 1to234 subCA Cert", "P1 Mapping 1to234 CA Cert"])
        .policies(&["NIST-test-policy-1"])
        .valid();

    Pkits::new()
        .end_entity("Valid Policy Mapping Test6 EE")
        .crls(&["P1 Mapping 1to234 subCA CRL", "P1 Mapping 1to234 CA CRL"])
        .certs(&["P1 Mapping 1to234 subCA Cert", "P1 Mapping 1to234 CA Cert"])
        .policies(&["NIST-test-policy-6"])
        .invalid(
            None,
            ValidatorReason::InvalidPolicy,
            "Path processing failed on policy.",
        );
}

// 4.10.7 Invalid Mapping From anyPolicy Test7
#[test]
fn pkits_4_10_7_invalid_mapping_from_anypolicy_test7() {
    Pkits::new()
        .end_entity("Invalid Mapping From anyPolicy Test7 EE")
        .crls(&["Mapping From anyPolicy CA CRL"])
        .certs(&["Mapping From anyPolicy CA Cert"])
        .invalid(
            Some(1),
            ValidatorReason::InvalidPolicy,
            "IssuerDomainPolicy is anyPolicy",
        );
}

// 4.10.8 Invalid Mapping To anyPolicy Test8
#[test]
fn pkits_4_10_8_invalid_mapping_to_anypolicy_test8() {
    Pkits::new()
        .end_entity("Invalid Mapping To anyPolicy Test8 EE")
        .crls(&["Mapping To anyPolicy CA CRL"])
        .certs(&["Mapping To anyPolicy CA Cert"])
        .invalid(
            Some(1),
            ValidatorReason::InvalidPolicy,
            "SubjectDomainPolicy is anyPolicy",
        );
}

// 4.10.9 Valid Policy Mapping Test9
#[test]
fn pkits_4_10_9_valid_policy_mapping_test9() {
    Pkits::new()
        .end_entity("Valid Policy Mapping Test9 EE")
        .crls(&["PanyPolicy Mapping 1to2 CA CRL"])
        .certs(&["PanyPolicy Mapping 1to2 CA Cert"])
        .valid();
}

// 4.10.10 Invalid Policy Mapping Test10
#[test]
fn pkits_4_10_10_invalid_policy_mapping_test10() {
    Pkits::new()
        .end_entity("Invalid Policy Mapping Test10 EE")
        .crls(&["Good subCA PanyPolicyMapping 1to2 CA CRL", "Good CA CRL"])
        .certs(&["Good subCA PanyPolicy Mapping 1to2 CA Cert", "Good CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.10.11 Valid Policy Mapping Test11
#[test]
fn pkits_4_10_11_valid_policy_mapping_test11() {
    Pkits::new()
        .end_entity("Valid Policy Mapping Test11 EE")
        .crls(&["Good subCA PanyPolicyMapping 1to2 CA CRL", "Good CA CRL"])
        .certs(&["Good subCA PanyPolicy Mapping 1to2 CA Cert", "Good CA Cert"])
        .valid();
}

// 4.10.12 Valid Policy Mapping Test12
#[test]
fn pkits_4_10_12_valid_policy_mapping_test12() {
    Pkits::new()
        .end_entity("Valid Policy Mapping Test12 EE")
        .crls(&["P12 Mapping 1to3 CA CRL"])
        .certs(&["P12 Mapping 1to3 CA Cert"])
        .policies(&["NIST-test-policy-1"])
        .valid();

    Pkits::new()
        .end_entity("Valid Policy Mapping Test12 EE")
        .crls(&["P12 Mapping 1to3 CA CRL"])
        .certs(&["P12 Mapping 1to3 CA Cert"])
        .policies(&["NIST-test-policy-2"])
        .valid();
}

// 4.10.13 Valid Policy Mapping Test13
#[test]
fn pkits_4_10_13_valid_policy_mapping_test13() {
    Pkits::new()
        .end_entity("Valid Policy Mapping Test13 EE")
        .crls(&["P1anyPolicy Mapping 1to2 CA CRL"])
        .certs(&["P1anyPolicy Mapping 1to2 CA Cert"])
        .valid();
}

// 4.10.14 Valid Policy Mapping Test14
#[test]
fn pkits_4_10_14_valid_policy_mapping_test14() {
    Pkits::new()
        .end_entity("Valid Policy Mapping Test14 EE")
        .crls(&["P1anyPolicy Mapping 1to2 CA CRL"])
        .certs(&["P1anyPolicy Mapping 1to2 CA Cert"])
        .valid();
}

// 4.11.1 Invalid inhibitPolicyMapping Test1
#[test]
fn pkits_4_11_1_invalid_inhibitpolicymapping_test1() {
    Pkits::new()
        .end_entity("Invalid inhibitPolicyMapping Test1 EE")
        .crls(&[
            "inhibitPolicyMapping0 subCA CRL",
            "inhibitPolicyMapping0 CA CRL",
        ])
        .certs(&[
            "inhibitPolicyMapping0 subCA Cert",
            "inhibitPolicyMapping0 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.11.2 Valid inhibitPolicyMapping Test2
#[test]
fn pkits_4_11_2_valid_inhibitpolicymapping_test2() {
    Pkits::new()
        .end_entity("Valid inhibitPolicyMapping Test2 EE")
        .crls(&[
            "inhibitPolicyMapping1 P12 subCACRL",
            "inhibitPolicyMapping1 P12 CA CRL",
        ])
        .certs(&[
            "inhibitPolicyMapping1 P12 subCA Cert",
            "inhibitPolicyMapping1 P12 CA Cert",
        ])
        .valid();
}

// 4.11.3 Invalid inhibitPolicyMapping Test3
#[test]
fn pkits_4_11_3_invalid_inhibitpolicymapping_test3() {
    Pkits::new()
        .end_entity("Invalid inhibitPolicyMapping Test3 EE")
        .crls(&[
            "inhibitPolicyMapping1 P12subsubCA CRL",
            "inhibitPolicyMapping1 P12 subCACRL",
            "inhibitPolicyMapping1 P12 CA CRL",
        ])
        .certs(&[
            "inhibitPolicyMapping1 P12 subsubCA Cert",
            "inhibitPolicyMapping1 P12 subCA Cert",
            "inhibitPolicyMapping1 P12 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.11.4 Valid inhibitPolicyMapping Test4
#[test]
fn pkits_4_11_4_valid_inhibitpolicymapping_test4() {
    Pkits::new()
        .end_entity("Valid inhibitPolicyMapping Test4 EE")
        .crls(&[
            "inhibitPolicyMapping1 P12subsubCA CRL",
            "inhibitPolicyMapping1 P12 subCACRL",
            "inhibitPolicyMapping1 P12 CA CRL",
        ])
        .certs(&[
            "inhibitPolicyMapping1 P12 subsubCA Cert",
            "inhibitPolicyMapping1 P12 subCA Cert",
            "inhibitPolicyMapping1 P12 CA Cert",
        ])
        .valid();
}

// 4.11.5 Invalid inhibitPolicyMapping Test5
#[test]
fn pkits_4_11_5_invalid_inhibitpolicymapping_test5() {
    Pkits::new()
        .end_entity("Invalid inhibitPolicyMapping Test5 EE")
        .crls(&[
            "inhibitPolicyMapping5subsubsubCA CRL",
            "inhibitPolicyMapping5 subsubCA CRL",
            "inhibitPolicyMapping5 subCA CRL",
            "inhibitPolicyMapping5 CA CRL",
        ])
        .certs(&[
            "inhibitPolicyMapping5 subsubsubCA Cert",
            "inhibitPolicyMapping5 subsubCA Cert",
            "inhibitPolicyMapping5 subCA Cert",
            "inhibitPolicyMapping5 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.11.6 Invalid inhibitPolicyMapping Test6
#[test]
fn pkits_4_11_6_invalid_inhibitpolicymapping_test6() {
    Pkits::new()
        .end_entity("Invalid inhibitPolicyMapping Test6 EE")
        .crls(&[
            "inhibitPolicyMapping1 P12subsubCAIPM5 CRL",
            "inhibitPolicyMapping1 P12subCAIPM5 CRL",
            "inhibitPolicyMapping1 P12 CA CRL",
        ])
        .certs(&[
            "inhibitPolicyMapping1 P12 subsubCAIPM5 Cert",
            "inhibitPolicyMapping1 P12 subCAIPM5 Cert",
            "inhibitPolicyMapping1 P12 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.11.7 Valid Self-Issued inhibitPolicyMapping Test7
#[test]
fn pkits_4_11_7_valid_self_issued_inhibitpolicymapping_test7() {
    Pkits::new()
        .end_entity("Valid SelfIssued inhibitPolicyMapping Test7 EE")
        .crls(&[
            "inhibitPolicyMapping1 P1 subCA CRL",
            "inhibitPolicyMapping1 P1 CA CRL",
        ])
        .certs(&[
            "inhibitPolicyMapping1 P1 subCA Cert",
            "inhibitPolicyMapping1 P1 SelfIssued CA Cert",
            "inhibitPolicyMapping1 P1 CA Cert",
        ])
        .valid();
}

// 4.11.8 Invalid Self-Issued inhibitPolicyMapping Test8
#[test]
fn pkits_4_11_8_invalid_self_issued_inhibitpolicymapping_test8() {
    Pkits::new()
        .end_entity("Invalid SelfIssued inhibitPolicyMapping Test8 EE")
        .crls(&[
            "inhibitPolicyMapping1 P1 subsubCACRL",
            "inhibitPolicyMapping1 P1 subCA CRL",
            "inhibitPolicyMapping1 P1 CA CRL",
        ])
        .certs(&[
            "inhibitPolicyMapping1 P1 subsubCA Cert",
            "inhibitPolicyMapping1 P1 subCA Cert",
            "inhibitPolicyMapping1 P1 SelfIssued CA Cert",
            "inhibitPolicyMapping1 P1 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.11.9 Invalid Self-Issued inhibitPolicyMapping Test9
#[test]
fn pkits_4_11_9_invalid_self_issued_inhibitpolicymapping_test9() {
    Pkits::new()
        .end_entity("Invalid SelfIssued inhibitPolicyMapping Test9 EE")
        .crls(&[
            "inhibitPolicyMapping1 P1 subsubCACRL",
            "inhibitPolicyMapping1 P1 subCA CRL",
            "inhibitPolicyMapping1 P1 CA CRL",
        ])
        .certs(&[
            "inhibitPolicyMapping1 P1 subsubCA Cert",
            "inhibitPolicyMapping1 P1 subCA Cert",
            "inhibitPolicyMapping1 P1 SelfIssued CA Cert",
            "inhibitPolicyMapping1 P1 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.11.10 Invalid Self-Issued inhibitPolicyMapping Test10
#[test]
fn pkits_4_11_10_invalid_self_issued_inhibitpolicymapping_test10() {
    Pkits::new()
        .end_entity("Invalid SelfIssued inhibitPolicyMapping Test10 EE")
        .certs(&[
            "inhibitPolicyMapping1 P1 SelfIssued subCA Cert",
            "inhibitPolicyMapping1 P1 subCA Cert",
            "inhibitPolicyMapping1 P1 SelfIssued CA Cert",
            "inhibitPolicyMapping1 P1 CA Cert",
        ])
        .crls(&[
            "inhibitPolicyMapping1 P1 subCA CRL",
            "inhibitPolicyMapping1 P1 CA CRL",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.11.11 Invalid Self-Issued inhibitPolicyMapping Test11
#[test]
fn pkits_4_11_11_invalid_self_issued_inhibitpolicymapping_test11() {
    Pkits::new()
        .end_entity("Invalid SelfIssued inhibitPolicyMapping Test11 EE")
        .certs(&[
            "inhibitPolicyMapping1 P1 SelfIssued subCA Cert",
            "inhibitPolicyMapping1 P1 subCA Cert",
            "inhibitPolicyMapping1 P1 SelfIssued CA Cert",
            "inhibitPolicyMapping1 P1 CA Cert",
        ])
        .crls(&[
            "inhibitPolicyMapping1 P1 subCA CRL",
            "inhibitPolicyMapping1 P1 CA CRL",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.12.1 Invalid inhibitAnyPolicy Test1
#[test]
fn pkits_4_12_1_invalid_inhibitanypolicy_test1() {
    Pkits::new()
        .end_entity("Invalid inhibitAnyPolicy Test1 EE")
        .crls(&["inhibitAnyPolicy0 CA CRL"])
        .certs(&["inhibitAnyPolicy0 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.12.2 Valid inhibitAnyPolicy Test2
#[test]
fn pkits_4_12_2_valid_inhibitanypolicy_test2() {
    Pkits::new()
        .end_entity("Valid inhibitAnyPolicy Test2 EE")
        .crls(&["inhibitAnyPolicy0 CA CRL"])
        .certs(&["inhibitAnyPolicy0 CA Cert"])
        .valid();
}

// 4.12.3 inhibitAnyPolicy Test3
#[test]
fn pkits_4_12_3_inhibitanypolicy_test3() {
    Pkits::new()
        .end_entity("inhibitAnyPolicy Test3 EE")
        .crls(&["inhibitAnyPolicy1 subCA1 CRL", "inhibitAnyPolicy1 CA CRL"])
        .certs(&["inhibitAnyPolicy1 subCA1 Cert", "inhibitAnyPolicy1 CA Cert"])
        .valid();

    Pkits::new()
        .end_entity("inhibitAnyPolicy Test3 EE")
        .crls(&["inhibitAnyPolicy1 subCA1 CRL", "inhibitAnyPolicy1 CA CRL"])
        .certs(&["inhibitAnyPolicy1 subCA1 Cert", "inhibitAnyPolicy1 CA Cert"])
        .any_policy_inhibited(true)
        .invalid(
            Some(1),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.12.4 Invalid inhibitAnyPolicy Test4
#[test]
fn pkits_4_12_4_invalid_inhibitanypolicy_test4() {
    Pkits::new()
        .end_entity("Invalid inhibitAnyPolicy Test4 EE")
        .crls(&["inhibitAnyPolicy1 subCA1 CRL", "inhibitAnyPolicy1 CA CRL"])
        .certs(&["inhibitAnyPolicy1 subCA1 Cert", "inhibitAnyPolicy1 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.12.5 Invalid inhibitAnyPolicy Test5
#[test]
fn pkits_4_12_5_invalid_inhibitanypolicy_test5() {
    Pkits::new()
        .end_entity("Invalid inhibitAnyPolicy Test5 EE")
        .crls(&[
            "inhibitAnyPolicy5 subsubCA CRL",
            "inhibitAnyPolicy5 subCA CRL",
            "inhibitAnyPolicy5 CA CRL",
        ])
        .certs(&[
            "inhibitAnyPolicy5 subsubCA Cert",
            "inhibitAnyPolicy5 subCA Cert",
            "inhibitAnyPolicy5 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.12.6 Invalid inhibitAnyPolicy Test6
#[test]
fn pkits_4_12_6_invalid_inhibitanypolicy_test6() {
    Pkits::new()
        .end_entity("Invalid inhibitAnyPolicy Test6 EE")
        .crls(&[
            "inhibitAnyPolicy1 subCAIAP5 CRL",
            "inhibitAnyPolicy1 CA CRL",
        ])
        .certs(&[
            "inhibitAnyPolicy1 subCAIAP5 Cert",
            "inhibitAnyPolicy1 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.12.7 Valid Self-Issued inhibitAnyPolicy Test7
#[test]
fn pkits_4_12_7_valid_self_issued_inhibitanypolicy_test7() {
    Pkits::new()
        .end_entity("Valid SelfIssued inhibitAnyPolicy Test7 EE")
        .crls(&["inhibitAnyPolicy1 subCA2 CRL", "inhibitAnyPolicy1 CA CRL"])
        .certs(&[
            "inhibitAnyPolicy1 subCA2 Cert",
            "inhibitAnyPolicy1 SelfIssued CA Cert",
            "inhibitAnyPolicy1 CA Cert",
        ])
        .valid();
}

// 4.12.8 Invalid Self-Issued inhibitAnyPolicy Test8
#[test]
fn pkits_4_12_8_invalid_self_issued_inhibitanypolicy_test8() {
    Pkits::new()
        .end_entity("Invalid SelfIssued inhibitAnyPolicy Test8 EE")
        .crls(&[
            "inhibitAnyPolicy1 subsubCA2 CRL",
            "inhibitAnyPolicy1 subCA2 CRL",
            "inhibitAnyPolicy1 CA CRL",
        ])
        .certs(&[
            "inhibitAnyPolicy1 subsubCA2 Cert",
            "inhibitAnyPolicy1 subCA2 Cert",
            "inhibitAnyPolicy1 SelfIssued CA Cert",
            "inhibitAnyPolicy1 CA Cert",
        ])
        .invalid(
            Some(1),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.12.9 Valid Self-Issued inhibitAnyPolicy Test9
#[test]
fn pkits_4_12_9_valid_self_issued_inhibitanypolicy_test9() {
    Pkits::new()
        .policies(&["NIST-test-policy-1"])
        .end_entity("Valid SelfIssued inhibitAnyPolicy Test9 EE")
        .certs(&[
            "inhibitAnyPolicy1 SelfIssued subCA2 Cert",
            "inhibitAnyPolicy1 subCA2 Cert",
            "inhibitAnyPolicy1 SelfIssued CA Cert",
            "inhibitAnyPolicy1 CA Cert",
        ])
        .crls(&["inhibitAnyPolicy1 subCA2 CRL", "inhibitAnyPolicy1 CA CRL"])
        .valid();
}

// 4.12.10 Invalid Self-Issued inhibitAnyPolicy Test10
#[test]
fn pkits_4_12_10_invalid_self_issued_inhibitanypolicy_test10() {
    Pkits::new()
        .end_entity("Invalid SelfIssued inhibitAnyPolicy Test10 EE")
        .crls(&["inhibitAnyPolicy1 subCA2 CRL", "inhibitAnyPolicy1 CA CRL"])
        .certs(&[
            "inhibitAnyPolicy1 subCA2 Cert",
            "inhibitAnyPolicy1 SelfIssued CA Cert",
            "inhibitAnyPolicy1 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidPolicy,
            "No valid policy tree found when one expected.",
        );
}

// 4.13.1 Valid DN nameConstraints Test1
#[test]
fn pkits_4_13_1_valid_dn_nameconstraints_test1() {
    Pkits::new()
        .end_entity("Valid DN nameConstraints Test1 EE")
        .crls(&["nameConstraints DN1 CA CRL"])
        .certs(&["nameConstraints DN1 CA Cert"])
        .valid();
}

// 4.13.2 Invalid DN nameConstraints Test2
#[test]
fn pkits_4_13_2_invalid_dn_nameconstraints_test2() {
    Pkits::new()
        .end_entity("Invalid DN nameConstraints Test2 EE")
        .crls(&["nameConstraints DN1 CA CRL"])
        .certs(&["nameConstraints DN1 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject failed.",
        );
}

// 4.13.3 Invalid DN nameConstraints Test3
#[test]
fn pkits_4_13_3_invalid_dn_nameconstraints_test3() {
    Pkits::new()
        .end_entity("Invalid DN nameConstraints Test3 EE")
        .crls(&["nameConstraints DN1 CA CRL"])
        .certs(&["nameConstraints DN1 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject alternative name failed.",
        );
}

// 4.13.4 Valid DN nameConstraints Test4
#[test]
fn pkits_4_13_4_valid_dn_nameconstraints_test4() {
    Pkits::new()
        .end_entity("Valid DN nameConstraints Test4 EE")
        .crls(&["nameConstraints DN1 CA CRL"])
        .certs(&["nameConstraints DN1 CA Cert"])
        .valid();
}

// 4.13.5 Valid DN nameConstraints Test5
#[test]
fn pkits_4_13_5_valid_dn_nameconstraints_test5() {
    Pkits::new()
        .end_entity("Valid DN nameConstraints Test5 EE")
        .crls(&["nameConstraints DN2 CA CRL"])
        .certs(&["nameConstraints DN2 CA Cert"])
        .valid();
}

// 4.13.6 Valid DN nameConstraints Test6
#[test]
fn pkits_4_13_6_valid_dn_nameconstraints_test6() {
    Pkits::new()
        .end_entity("Valid DN nameConstraints Test6 EE")
        .crls(&["nameConstraints DN3 CA CRL"])
        .certs(&["nameConstraints DN3 CA Cert"])
        .valid();
}

// 4.13.7 Invalid DN nameConstraints Test7
#[test]
fn pkits_4_13_7_invalid_dn_nameconstraints_test7() {
    Pkits::new()
        .end_entity("Invalid DN nameConstraints Test7 EE")
        .crls(&["nameConstraints DN3 CA CRL"])
        .certs(&["nameConstraints DN3 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject failed.",
        );
}

// 4.13.8 Invalid DN nameConstraints Test8
#[test]
fn pkits_4_13_8_invalid_dn_nameconstraints_test8() {
    Pkits::new()
        .end_entity("Invalid DN nameConstraints Test8 EE")
        .crls(&["nameConstraints DN4 CA CRL"])
        .certs(&["nameConstraints DN4 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject failed.",
        );
}

// 4.13.9 Invalid DN nameConstraints Test9
#[test]
fn pkits_4_13_9_invalid_dn_nameconstraints_test9() {
    Pkits::new()
        .end_entity("Invalid DN nameConstraints Test9 EE")
        .crls(&["nameConstraints DN4 CA CRL"])
        .certs(&["nameConstraints DN4 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject failed.",
        );
}

// 4.13.10 Invalid DN nameConstraints Test10
#[test]
fn pkits_4_13_10_invalid_dn_nameconstraints_test10() {
    Pkits::new()
        .end_entity("Invalid DN nameConstraints Test10 EE")
        .crls(&["nameConstraints DN5 CA CRL"])
        .certs(&["nameConstraints DN5 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject failed.",
        );
}

// 4.13.11 Valid DN nameConstraints Test11
#[test]
fn pkits_4_13_11_valid_dn_nameconstraints_test11() {
    Pkits::new()
        .end_entity("Valid DN nameConstraints Test11 EE")
        .crls(&["nameConstraints DN5 CA CRL"])
        .certs(&["nameConstraints DN5 CA Cert"])
        .valid();
}

// 4.13.12 Invalid DN nameConstraints Test12
#[test]
fn pkits_4_13_12_invalid_dn_nameconstraints_test12() {
    Pkits::new()
        .end_entity("Invalid DN nameConstraints Test12 EE")
        .crls(&[
            "nameConstraints DN1 subCA1 CRL",
            "nameConstraints DN1 CA CRL",
        ])
        .certs(&[
            "nameConstraints DN1 subCA1 Cert",
            "nameConstraints DN1 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject failed.",
        );
}

// 4.13.13 Invalid DN nameConstraints Test13
#[test]
fn pkits_4_13_13_invalid_dn_nameconstraints_test13() {
    Pkits::new()
        .end_entity("Invalid DN nameConstraints Test13 EE")
        .crls(&[
            "nameConstraints DN1 subCA2 CRL",
            "nameConstraints DN1 CA CRL",
        ])
        .certs(&[
            "nameConstraints DN1 subCA2 Cert",
            "nameConstraints DN1 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject failed.",
        );
}

// 4.13.14 Valid DN nameConstraints Test14
#[test]
fn pkits_4_13_14_valid_dn_nameconstraints_test14() {
    Pkits::new()
        .end_entity("Valid DN nameConstraints Test14 EE")
        .crls(&[
            "nameConstraints DN1 subCA2 CRL",
            "nameConstraints DN1 CA CRL",
        ])
        .certs(&[
            "nameConstraints DN1 subCA2 Cert",
            "nameConstraints DN1 CA Cert",
        ])
        .valid();
}

// 4.13.15 Invalid DN nameConstraints Test15
#[test]
fn pkits_4_13_15_invalid_dn_nameconstraints_test15() {
    Pkits::new()
        .end_entity("Invalid DN nameConstraints Test15 EE")
        .crls(&[
            "nameConstraints DN3 subCA1 CRL",
            "nameConstraints DN3 CA CRL",
        ])
        .certs(&[
            "nameConstraints DN3 subCA1 Cert",
            "nameConstraints DN3 CA Cert",
        ])
        .invalid(
            Some(00),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject failed.",
        );
}

// 4.13.16 Invalid DN nameConstraints Test16
#[test]
fn pkits_4_13_16_invalid_dn_nameconstraints_test16() {
    Pkits::new()
        .end_entity("Invalid DN nameConstraints Test16 EE")
        .crls(&[
            "nameConstraints DN3 subCA1 CRL",
            "nameConstraints DN3 CA CRL",
        ])
        .certs(&[
            "nameConstraints DN3 subCA1 Cert",
            "nameConstraints DN3 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject failed.",
        );
}

// 4.13.17 Invalid DN nameConstraints Test17
#[test]
fn pkits_4_13_17_invalid_dn_nameconstraints_test17() {
    Pkits::new()
        .end_entity("Invalid DN nameConstraints Test17 EE")
        .crls(&[
            "nameConstraints DN3 subCA2 CRL",
            "nameConstraints DN3 CA CRL",
        ])
        .certs(&[
            "nameConstraints DN3 subCA2 Cert",
            "nameConstraints DN3 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject failed.",
        );
}

// 4.13.18 Valid DN nameConstraints Test18
#[test]
fn pkits_4_13_18_valid_dn_nameconstraints_test18() {
    Pkits::new()
        .end_entity("Valid DN nameConstraints Test18 EE")
        .crls(&[
            "nameConstraints DN3 subCA2 CRL",
            "nameConstraints DN3 CA CRL",
        ])
        .certs(&[
            "nameConstraints DN3 subCA2 Cert",
            "nameConstraints DN3 CA Cert",
        ])
        .valid();
}

// 4.13.19 Valid Self-Issued DN nameConstraints Test19
#[test]
fn pkits_4_13_19_valid_self_issued_dn_nameconstraints_test19() {
    Pkits::new()
        .end_entity("Valid DN nameConstraints Test19 EE")
        .certs(&[
            "nameConstraints DN1 SelfIssued CA Cert",
            "nameConstraints DN1 CA Cert",
        ])
        .crls(&["nameConstraints DN1 CA CRL"])
        .valid();
}

// 4.13.20 Invalid Self-Issued DN nameConstraints Test20
#[test]
fn pkits_4_13_20_invalid_self_issued_dn_nameconstraints_test20() {
    Pkits::new()
        .end_entity("Invalid DN nameConstraints Test20 EE")
        .crls(&["nameConstraints DN1 CA CRL"])
        .certs(&["nameConstraints DN1 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject failed.",
        );
}

// 4.13.21 Valid RFC822 nameConstraints Test21
#[test]
fn pkits_4_13_21_valid_rfc822_nameconstraints_test21() {
    Pkits::new()
        .end_entity("Valid RFC822 nameConstraints Test21 EE")
        .crls(&["nameConstraints RFC822 CA1 CRL"])
        .certs(&["nameConstraints RFC822 CA1 Cert"])
        .valid();
}

// 4.13.22 Invalid RFC822 nameConstraints Test22
#[test]
fn pkits_4_13_22_invalid_rfc822_nameconstraints_test22() {
    Pkits::new()
        .end_entity("Invalid RFC822 nameConstraints Test22 EE")
        .crls(&["nameConstraints RFC822 CA1 CRL"])
        .certs(&["nameConstraints RFC822 CA1 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject alternative name failed.",
        );
}

// 4.13.23 Valid RFC822 nameConstraints Test23
#[test]
fn pkits_4_13_23_valid_rfc822_nameconstraints_test23() {
    Pkits::new()
        .end_entity("Valid RFC822 nameConstraints Test23 EE")
        .crls(&["nameConstraints RFC822 CA2 CRL"])
        .certs(&["nameConstraints RFC822 CA2 Cert"])
        .valid();
}

// 4.13.24 Invalid RFC822 nameConstraints Test24
#[test]
fn pkits_4_13_24_invalid_rfc822_nameconstraints_test24() {
    Pkits::new()
        .end_entity("Invalid RFC822 nameConstraints Test24 EE")
        .crls(&["nameConstraints RFC822 CA2 CRL"])
        .certs(&["nameConstraints RFC822 CA2 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject alternative name failed.",
        );
}

// 4.13.25 Valid RFC822 nameConstraints Test25
#[test]
fn pkits_4_13_25_valid_rfc822_nameconstraints_test25() {
    Pkits::new()
        .end_entity("Valid RFC822 nameConstraints Test25 EE")
        .crls(&["nameConstraints RFC822 CA3 CRL"])
        .certs(&["nameConstraints RFC822 CA3 Cert"])
        .valid();
}

// 4.13.26 Invalid RFC822 nameConstraints Test26
#[test]
fn pkits_4_13_26_invalid_rfc822_nameconstraints_test26() {
    Pkits::new()
        .end_entity("Invalid RFC822 nameConstraints Test26 EE")
        .crls(&["nameConstraints RFC822 CA3 CRL"])
        .certs(&["nameConstraints RFC822 CA3 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject alternative name failed.",
        );
}

// 4.13.27 Valid DN and RFC822 nameConstraints Test27
#[test]
fn pkits_4_13_27_valid_dn_and_rfc822_nameconstraints_test27() {
    Pkits::new()
        .end_entity("Valid DN and RFC822 nameConstraints Test27 EE")
        .crls(&[
            "nameConstraints DN1 subCA3 CRL",
            "nameConstraints DN1 CA CRL",
        ])
        .certs(&[
            "nameConstraints DN1 subCA3 Cert",
            "nameConstraints DN1 CA Cert",
        ])
        .valid();
}

// 4.13.28 Invalid DN and RFC822 nameConstraints Test28
#[test]
fn pkits_4_13_28_invalid_dn_and_rfc822_nameconstraints_test28() {
    Pkits::new()
        .end_entity("Invalid DN and RFC822 nameConstraints Test28 EE")
        .crls(&[
            "nameConstraints DN1 subCA3 CRL",
            "nameConstraints DN1 CA CRL",
        ])
        .certs(&[
            "nameConstraints DN1 subCA3 Cert",
            "nameConstraints DN1 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject alternative name failed.",
        );
}

// 4.13.29 Invalid DN and RFC822 nameConstraints Test29
#[test]
fn pkits_4_13_29_invalid_dn_and_rfc822_nameconstraints_test29() {
    Pkits::new()
        .end_entity("Invalid DN and RFC822 nameConstraints Test29 EE")
        .crls(&[
            "nameConstraints DN1 subCA3 CRL",
            "nameConstraints DN1 CA CRL",
        ])
        .certs(&[
            "nameConstraints DN1 subCA3 Cert",
            "nameConstraints DN1 CA Cert",
        ])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject alternative email failed.",
        );
}

// 4.13.30 Valid DNS nameConstraints Test30
#[test]
fn pkits_4_13_30_valid_dns_nameconstraints_test30() {
    Pkits::new()
        .end_entity("Valid DNS nameConstraints Test30 EE")
        .crls(&["nameConstraints DNS1 CA CRL"])
        .certs(&["nameConstraints DNS1 CA Cert"])
        .valid();
}

// 4.13.31 Invalid DNS nameConstraints Test31
#[test]
fn pkits_4_13_31_invalid_dns_nameconstraints_test31() {
    Pkits::new()
        .end_entity("Invalid DNS nameConstraints Test31 EE")
        .crls(&["nameConstraints DNS1 CA CRL"])
        .certs(&["nameConstraints DNS1 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject alternative name failed.",
        );
}

// 4.13.32 Valid DNS nameConstraints Test32
#[test]
fn pkits_4_13_32_valid_dns_nameconstraints_test32() {
    Pkits::new()
        .end_entity("Valid DNS nameConstraints Test32 EE")
        .crls(&["nameConstraints DNS2 CA CRL"])
        .certs(&["nameConstraints DNS2 CA Cert"])
        .valid();
}

// 4.13.33 Invalid DNS nameConstraints Test33
#[test]
fn pkits_4_13_33_invalid_dns_nameconstraints_test33() {
    Pkits::new()
        .end_entity("Invalid DNS nameConstraints Test33 EE")
        .crls(&["nameConstraints DNS2 CA CRL"])
        .certs(&["nameConstraints DNS2 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject alternative name failed.",
        );
}

// 4.13.34 Valid URI nameConstraints Test34
#[test]
fn pkits_4_13_34_valid_uri_nameconstraints_test34() {
    Pkits::new()
        .end_entity("Valid URI nameConstraints Test34 EE")
        .crls(&["nameConstraints URI1 CA CRL"])
        .certs(&["nameConstraints URI1 CA Cert"])
        .valid();
}

// 4.13.35 Invalid URI nameConstraints Test35
#[test]
fn pkits_4_13_35_invalid_uri_nameconstraints_test35() {
    Pkits::new()
        .end_entity("Invalid URI nameConstraints Test35 EE")
        .crls(&["nameConstraints URI1 CA CRL"])
        .certs(&["nameConstraints URI1 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject alternative name failed.",
        );
}

// 4.13.36 Valid URI nameConstraints Test36
#[test]
fn pkits_4_13_36_valid_uri_nameconstraints_test36() {
    Pkits::new()
        .end_entity("Valid URI nameConstraints Test36 EE")
        .crls(&["nameConstraints URI2 CA CRL"])
        .certs(&["nameConstraints URI2 CA Cert"])
        .valid();
}

// 4.13.37 Invalid URI nameConstraints Test37
#[test]
fn pkits_4_13_37_invalid_uri_nameconstraints_test37() {
    Pkits::new()
        .end_entity("Invalid URI nameConstraints Test37 EE")
        .crls(&["nameConstraints URI2 CA CRL"])
        .certs(&["nameConstraints URI2 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject alternative name failed.",
        );
}

// 4.13.38 Invalid DNS nameConstraints Test38
#[test]
fn pkits_4_13_38_invalid_dns_nameconstraints_test38() {
    Pkits::new()
        .end_entity("Invalid DNS nameConstraints Test38 EE")
        .crls(&["nameConstraints DNS1 CA CRL"])
        .certs(&["nameConstraints DNS1 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::InvalidName,
            "Subtree check for certificate subject alternative name failed.",
        );
}

// 4.14.1 Valid distributionPoint Test1
#[test]
fn pkits_4_14_1_valid_distributionpoint_test1() {
    Pkits::new()
        .end_entity("Valid distributionPoint Test1 EE")
        .crls(&["distributionPoint1 CA CRL"])
        .certs(&["distributionPoint1 CA Cert"])
        .valid();
}

// 4.14.2 Invalid distributionPoint Test2
#[test]
fn pkits_4_14_2_invalid_distributionpoint_test2() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid distributionPoint Test2 EE")
        .crls(&["distributionPoint1 CA CRL"])
        .certs(&["distributionPoint1 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.14.3 Invalid distributionPoint Test3
#[test]
fn pkits_4_14_3_invalid_distributionpoint_test3() {
    Pkits::new()
        .end_entity("Invalid distributionPoint Test3 EE")
        .crls(&["distributionPoint1 CA CRL"])
        .certs(&["distributionPoint1 CA Cert"])
        .invalid_prefix(Some(0), ValidatorReason::UndeterminedRevocationStatus, "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
}

// 4.14.4 Valid distributionPoint Test4
#[test]
fn pkits_4_14_4_valid_distributionpoint_test4() {
    Pkits::new()
        .end_entity("Valid distributionPoint Test4 EE")
        .crls(&["distributionPoint1 CA CRL"])
        .certs(&["distributionPoint1 CA Cert"])
        .valid();
}

// 4.14.5 Valid distributionPoint Test5
#[test]
fn pkits_4_14_5_valid_distributionpoint_test5() {
    Pkits::new()
        .end_entity("Valid distributionPoint Test5 EE")
        .crls(&["distributionPoint2 CA CRL"])
        .certs(&["distributionPoint2 CA Cert"])
        .valid();
}

// 4.14.6 Invalid distributionPoint Test6
#[test]
fn pkits_4_14_6_invalid_distributionpoint_test6() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid distributionPoint Test6 EE")
        .crls(&["distributionPoint2 CA CRL"])
        .certs(&["distributionPoint2 CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.14.7 Valid distributionPoint Test7
#[test]
fn pkits_4_14_7_valid_distributionpoint_test7() {
    Pkits::new()
        .end_entity("Valid distributionPoint Test7 EE")
        .crls(&["distributionPoint2 CA CRL"])
        .certs(&["distributionPoint2 CA Cert"])
        .valid();
}

// 4.14.8 Invalid distributionPoint Test8
#[test]
fn pkits_4_14_8_invalid_distributionpoint_test8() {
    Pkits::new()
        .end_entity("Invalid distributionPoint Test8 EE")
        .crls(&["distributionPoint2 CA CRL"])
        .certs(&["distributionPoint2 CA Cert"])
        .invalid_prefix(Some(0), ValidatorReason::UndeterminedRevocationStatus, "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
}

// 4.14.9 Invalid distributionPoint Test9
#[test]
fn pkits_4_14_9_invalid_distributionpoint_test9() {
    Pkits::new()
        .end_entity("Invalid distributionPoint Test9 EE")
        .crls(&["distributionPoint2 CA CRL"])
        .certs(&["distributionPoint2 CA Cert"])
        .invalid_prefix(Some(0), ValidatorReason::UndeterminedRevocationStatus, "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
}

// 4.14.10 Valid No issuingDistributionPoint Test10
#[test]
fn pkits_4_14_10_valid_no_issuingdistributionpoint_test10() {
    Pkits::new()
        .end_entity("Valid No issuingDistributionPoint Test10 EE")
        .crls(&["No issuingDistributionPoint CA CRL"])
        .certs(&["No issuingDistributionPoint CA Cert"])
        .valid();
}

// 4.14.11 Invalid onlyContainsUserCerts CRL Test11
#[test]
fn pkits_4_14_11_invalid_onlycontainsusercerts_crl_test11() {
    Pkits::new()
        .end_entity("Invalid onlyContainsUserCerts Test11 EE")
        .crls(&["onlyContainsUserCerts CA CRL"])
        .certs(&["onlyContainsUserCerts CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "CA Cert CRL only contains user certificates.",
        );
}

// 4.14.12 Invalid onlyContainsCACerts CRL Test12
#[test]
fn pkits_4_14_12_invalid_onlycontainscacerts_crl_test12() {
    Pkits::new()
        .end_entity("Invalid onlyContainsCACerts Test12 EE")
        .crls(&["onlyContainsCACerts CA CRL"])
        .certs(&["onlyContainsCACerts CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "End CRL only contains CA certificates.",
        );
}

// 4.14.13 Valid onlyContainsCACerts CRL Test13
#[test]
fn pkits_4_14_13_valid_onlycontainscacerts_crl_test13() {
    Pkits::new()
        .end_entity("Valid onlyContainsCACerts Test13 EE")
        .crls(&["onlyContainsCACerts CA CRL"])
        .certs(&["onlyContainsCACerts CA Cert"])
        .valid();
}

// 4.14.14 Invalid onlyContainsAttributeCerts Test14
#[test]
fn pkits_4_14_14_invalid_onlycontainsattributecerts_test14() {
    Pkits::new()
        .end_entity("Invalid onlyContainsAttributeCerts Test14 EE")
        .crls(&["onlyContainsAttributeCerts CA CRL"])
        .certs(&["onlyContainsAttributeCerts CA Cert"])
        .invalid(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "onlyContainsAttributeCerts boolean is asserted.",
        );
}

// 4.14.15 Invalid onlySomeReasons Test15
#[test]
fn pkits_4_14_15_invalid_onlysomereasons_test15() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid onlySomeReasons Test15 EE")
        .crls(&[
            "onlySomeReasons CA1 other reasons CRL",
            "onlySomeReasons CA1 compromise CRL",
        ])
        .certs(&["onlySomeReasons CA1 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.14.16 Invalid onlySomeReasons Test16
#[test]
fn pkits_4_14_16_invalid_onlysomereasons_test16() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid onlySomeReasons Test16 EE")
        .crls(&[
            "onlySomeReasons CA1 other reasons CRL",
            "onlySomeReasons CA1 compromise CRL",
        ])
        .certs(&["onlySomeReasons CA1 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: certificateHold"),
        );
}

// 4.14.17 Invalid onlySomeReasons Test17
#[test]
fn pkits_4_14_17_invalid_onlysomereasons_test17() {
    Pkits::new()
        .end_entity("Invalid onlySomeReasons Test17 EE")
        .crls(&["onlySomeReasonsCA2 CRL2", "onlySomeReasons CA2 CRL1"])
        .certs(&["onlySomeReasons CA2 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "Certificate status could not be determined.",
        );
}

// 4.14.18 Valid onlySomeReasons Test18
#[test]
fn pkits_4_14_18_valid_onlysomereasons_test18() {
    Pkits::new()
        .end_entity("Valid onlySomeReasons Test18 EE")
        .crls(&[
            "onlySomeReasons CA3 other reasons CRL",
            "onlySomeReasons CA3 compromise CRL",
        ])
        .certs(&["onlySomeReasons CA3 Cert"])
        .valid();
}

// 4.14.19 Valid onlySomeReasons Test19
#[test]
fn pkits_4_14_19_valid_onlysomereasons_test19() {
    Pkits::new()
        .end_entity("Valid onlySomeReasons Test19 EE")
        .crls(&[
            "onlySomeReasons CA4 other reasons CRL",
            "onlySomeReasons CA4 compromise CRL",
        ])
        .certs(&["onlySomeReasons CA4 Cert"])
        .valid();
}

// 4.14.20 Invalid onlySomeReasons Test20
#[test]
fn pkits_4_14_20_invalid_onlysomereasons_test20() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid onlySomeReasons Test20 EE")
        .crls(&[
            "onlySomeReasons CA4 other reasons CRL",
            "onlySomeReasons CA4 compromise CRL",
        ])
        .certs(&["onlySomeReasons CA4 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.14.21 Invalid onlySomeReasons Test21
#[test]
fn pkits_4_14_21_invalid_onlysomereasons_test21() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid onlySomeReasons Test21 EE")
        .crls(&[
            "onlySomeReasons CA4 other reasons CRL",
            "onlySomeReasons CA4 compromise CRL",
        ])
        .certs(&["onlySomeReasons CA4 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: affiliationChanged"),
        );
}

// 4.14.22 Valid IDP with indirectCRL Test22
#[test]
fn pkits_4_14_22_valid_idp_with_indirectcrl_test22() {
    Pkits::new()
        .end_entity("Valid IDP with indirectCRL Test22 EE")
        .crls(&["indirectCRL CA1 CRL"])
        .certs(&["indirectCRL CA1 Cert"])
        .valid();
}

// 4.14.23 Invalid IDP with indirectCRL Test23
#[test]
fn pkits_4_14_23_invalid_idp_with_indirectcrl_test23() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid IDP with indirectCRL Test23 EE")
        .crls(&["indirectCRL CA1 CRL"])
        .certs(&["indirectCRL CA1 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.14.24 Valid IDP with indirectCRL Test24
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK"]
fn pkits_4_14_24_valid_idp_with_indirectcrl_test24() {
    Pkits::new()
        .end_entity("Valid IDP with indirectCRL Test24 EE")
        .crls(&["indirectCRL CA1 CRL"])
        .certs(&["indirectCRL CA1 Cert", "indirectCRL CA2 Cert"])
        .valid();
}

// 4.14.25 Valid IDP with indirectCRL Test25
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK"]
fn pkits_4_14_25_valid_idp_with_indirectcrl_test25() {
    Pkits::new()
        .end_entity("Valid IDP with indirectCRL Test25 EE")
        .crls(&["indirectCRL CA1 CRL"])
        .certs(&["indirectCRL CA1 Cert", "indirectCRL CA2 Cert"])
        .valid();
}

// 4.14.26 Invalid IDP with indirectCRL Test26
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK not forming path, 'Trust anchor for certification path not found.'"]
fn pkits_4_14_26_invalid_idp_with_indirectcrl_test26() {
    Pkits::new()
        .end_entity("Invalid IDP with indirectCRL Test26 EE")
        .crls(&["indirectCRL CA1 CRL"])
        .certs(&["indirectCRL CA1 Cert", "indirectCRL CA2 Cert"])
        .invalid(None, ValidatorReason::UndeterminedRevocationStatus, "--");
}

// 4.14.27 Invalid cRLIssuer Test27
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK not forming path, 'Trust anchor for certification path not found.'"]
fn pkits_4_14_27_invalid_crlissuer_test27() {
    Pkits::new()
        .end_entity("Invalid cRLIssuer Test27 EE")
        .crls(&["Good CA CRL"])
        .certs(&["Good CA Cert", "indirectCRL CA2 Cert"])
        .invalid(None, ValidatorReason::UndeterminedRevocationStatus, "--");
}

// 4.14.28 Valid cRLIssuer Test28
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK"]
fn pkits_4_14_28_valid_crlissuer_test28() {
    Pkits::new()
        .end_entity("Valid cRLIssuer Test28 EE")
        .crls(&["indirectCRL CA3 cRLIssuer CRL", "indirectCRL CA3 CRL"])
        .certs(&["indirectCRL CA3 cRLIssuer Cert", "indirectCRL CA3 Cert"])
        .valid();
}

// 4.14.29 Valid cRLIssuer Test29
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK"]
fn pkits_4_14_29_valid_crlissuer_test29() {
    Pkits::new()
        .end_entity("Valid cRLIssuer Test29 EE")
        .crls(&["indirectCRL CA3 cRLIssuer CRL", "indirectCRL CA3 CRL"])
        .certs(&["indirectCRL CA3 cRLIssuer Cert", "indirectCRL CA3 Cert"])
        .valid();
}

// 4.14.30 Valid cRLIssuer Test30
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK"]
fn pkits_4_14_30_valid_crlissuer_test30() {
    Pkits::new()
        .end_entity("Valid cRLIssuer Test30 EE")
        .crls(&["indirectCRL CA4 cRLIssuer CRL"])
        .certs(&["indirectCRL CA4 cRLIssuer Cert", "indirectCRL CA4 Cert"])
        .valid();
}

// 4.14.31 Invalid cRLIssuer Test31
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK not forming path, 'Trust anchor for certification path not found.'"]
fn pkits_4_14_31_invalid_crlissuer_test31() {
    Pkits::new()
        .end_entity("Invalid cRLIssuer Test31 EE")
        .certs(&["indirectCRL CA6 Cert", "indirectCRL CA5 Cert"])
        .crls(&["indirectCRL CA5 CRL"])
        .invalid(None, ValidatorReason::Revoked, "--");
}

// 4.14.32 Invalid cRLIssuer Test32
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK not forming path, 'Trust anchor for certification path not found.'"]
fn pkits_4_14_32_invalid_crlissuer_test32() {
    let expected_date = revocation_date(2001, 4, 19, 14, 57, 20);
    Pkits::new()
        .end_entity("Invalid cRLIssuer Test32 EE")
        .certs(&["indirectCRL CA6 Cert", "indirectCRL CA5 Cert"])
        .crls(&["indirectCRL CA5 CRL"])
        .invalid(
            None,
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.14.33 Valid cRLIssuer Test33
#[test]
#[ignore = "Bouncy Castle ignores it as well: CHECK"]
fn pkits_4_14_33_valid_crlissuer_test33() {
    Pkits::new()
        .end_entity("Valid cRLIssuer Test33 EE")
        .certs(&["indirectCRL CA6 Cert", "indirectCRL CA5 Cert"])
        .crls(&["indirectCRL CA5 CRL"])
        .valid();
}

// 4.14.34 Invalid cRLIssuer Test34
#[test]
fn pkits_4_14_34_invalid_crlissuer_test34() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid cRLIssuer Test34 EE")
        .crls(&["indirectCRL CA5 CRL"])
        .certs(&["indirectCRL CA5 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.14.35 Invalid cRLIssuer Test35
#[test]
fn pkits_4_14_35_invalid_crlissuer_test35() {
    Pkits::new()
        .end_entity("Invalid cRLIssuer Test35 EE")
        .crls(&["indirectCRL CA5 CRL"])
        .certs(&["indirectCRL CA5 Cert"])
        .invalid_prefix(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "No CRLs found for issuer ",
        );
}

// 4.15.1 Invalid deltaCRLIndicator No Base Test1
#[test]
fn pkits_4_15_1_invalid_deltacrlindicator_no_base_test1() {
    Pkits::new()
        .end_entity("Invalid deltaCRLIndicator No Base Test1 EE")
        .crls(&["deltaCRLIndicator No Base CA CRL"])
        .certs(&["deltaCRLIndicator No Base CA Cert"])
        .invalid_prefix(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "No CRLs found for issuer ",
        );
}

// 4.15.2 Valid delta-CRL Test2
#[test]
fn pkits_4_15_2_valid_delta_crl_test2() {
    Pkits::new()
        .end_entity("Valid deltaCRL Test2 EE")
        .crls(&["deltaCRL CA1 deltaCRL", "deltaCRL CA1 CRL"])
        .certs(&["deltaCRL CA1 Cert"])
        .valid();
}

// 4.15.3 Invalid delta-CRL Test3
#[test]
fn pkits_4_15_3_invalid_delta_crl_test3() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid deltaCRL Test3 EE")
        .crls(&["deltaCRL CA1 deltaCRL", "deltaCRL CA1 CRL"])
        .certs(&["deltaCRL CA1 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.15.4 Invalid delta-CRL Test4
#[test]
fn pkits_4_15_4_invalid_delta_crl_test4() {
    let expected_date = revocation_date(2010, 6, 1, 8, 30, 0);
    Pkits::new()
        .delta_crls(true)
        .end_entity("Invalid deltaCRL Test4 EE")
        .crls(&["deltaCRL CA1 deltaCRL", "deltaCRL CA1 CRL"])
        .certs(&["deltaCRL CA1 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.15.5 Valid delta-CRL Test5
#[test]
fn pkits_4_15_5_valid_delta_crl_test5() {
    Pkits::new()
        .delta_crls(true)
        .end_entity("Valid deltaCRL Test5 EE")
        .crls(&["deltaCRL CA1 deltaCRL", "deltaCRL CA1 CRL"])
        .certs(&["deltaCRL CA1 Cert"])
        .valid();
}

// 4.15.6 Invalid delta-CRL Test6
#[test]
fn pkits_4_15_6_invalid_delta_crl_test6() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .delta_crls(true)
        .end_entity("Invalid deltaCRL Test6 EE")
        .crls(&["deltaCRL CA1 deltaCRL", "deltaCRL CA1 CRL"])
        .certs(&["deltaCRL CA1 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.15.7 Valid delta-CRL Test7
#[test]
fn pkits_4_15_7_valid_delta_crl_test7() {
    Pkits::new()
        .end_entity("Valid deltaCRL Test7 EE")
        .crls(&["deltaCRL CA1 deltaCRL", "deltaCRL CA1 CRL"])
        .certs(&["deltaCRL CA1 Cert"])
        .valid();
}

// 4.15.8 Valid delta-CRL Test8
#[test]
fn pkits_4_15_8_valid_delta_crl_test8() {
    Pkits::new()
        .end_entity("Valid deltaCRL Test8 EE")
        .crls(&["deltaCRL CA2 deltaCRL", "deltaCRL CA2 CRL"])
        .certs(&["deltaCRL CA2 Cert"])
        .valid();
}

// 4.15.9 Invalid delta-CRL Test9
#[test]
fn pkits_4_15_9_invalid_delta_crl_test9() {
    let expected_date = revocation_date(2010, 1, 1, 8, 30, 0);
    Pkits::new()
        .end_entity("Invalid deltaCRL Test9 EE")
        .crls(&["deltaCRL CA2 deltaCRL", "deltaCRL CA2 CRL"])
        .certs(&["deltaCRL CA2 Cert"])
        .invalid(
            Some(0),
            ValidatorReason::Revoked,
            &format!("Certificate revocation after {expected_date}, reason: keyCompromise"),
        );
}

// 4.15.10 Invalid delta-CRL Test10
#[test]
fn pkits_4_15_10_invalid_delta_crl_test10() {
    Pkits::new()
        .delta_crls(true)
        .end_entity("Invalid deltaCRL Test10 EE")
        .crls(&["deltaCRL CA3 deltaCRL", "deltaCRL CA3 CRL"])
        .certs(&["deltaCRL CA3 Cert"])
        .invalid_prefix(
            Some(0),
            ValidatorReason::UndeterminedRevocationStatus,
            "No CRLs found for issuer ",
        );
}

// 4.16.1 Valid Unknown Not Critical Certificate Extension Test1
#[test]
fn pkits_4_16_1_valid_unknown_not_critical_certificate_extension_test1() {
    Pkits::new()
        .end_entity("Valid Unknown Not Critical Certificate Extension Test1 EE")
        .valid();
}

// 4.16.2 Invalid Unknown Critical Certificate Extension Test2
#[test]
fn pkits_4_16_2_invalid_unknown_critical_certificate_extension_test2() {
    Pkits::new()
        .end_entity("Invalid Unknown Critical Certificate Extension Test2 EE")
        .invalid(
            Some(0),
            ValidatorReason::UnrecognizedCriticalExtension,
            "Certificate has unsupported critical extension: [2.16.840.1.101.2.1.12.2]",
        );
}
