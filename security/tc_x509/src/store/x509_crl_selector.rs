use core::cmp::Ordering;

use tc_asn1::{Asn1Integer, DecodingContext, DecodingOptions};
use tc_asn1_x500::Name;
use tc_asn1_x509::cert::Time;
use tc_asn1_x509::crl::CrlNumber;
use tc_asn1_x509::ext::ExtensionId;

use crate::crl::X509Crl;

/// Selects CRLs by the criteria set on it, BC's `X509CrlStoreSelector`; a criterion not set
/// selects every CRL. Use it with an iterator: `crls.iter().filter(|c| selector.matches(c))`.
///
/// # Examples
///
/// The CRL of CN=Test CA, as read from a file:
///
/// ```
/// use tc_asn1::Asn1Integer;
/// use tc_x509::crl::X509Crl;
/// use tc_x509::store::X509CrlSelector;
///
/// let path = format!("{}/tests/data/crl/crl.der", env!("CARGO_MANIFEST_DIR"));
/// let crls = vec![X509Crl::decode(&std::fs::read(path)?)?];
///
/// // The CRLs of an issuer in force when it published, from CRL number 1 on
/// let selector = X509CrlSelector::new()
///     .with_issuer(crls[0].issuer().clone())
///     .with_date_and_time(crls[0].this_update())
///     .with_min_crl_number(Asn1Integer::from(1));
/// let current = crls.iter().find(|c| selector.matches(c));
/// println!("{:?}", current.map(|c| c.this_update()));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct X509CrlSelector {
    issuers: Vec<Name>,
    date_and_time: Option<Time>,
    min_crl_number: Option<Asn1Integer>,
    max_crl_number: Option<Asn1Integer>,
}

impl X509CrlSelector {
    /// A selector of every CRL. Constant time.
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects the CRLs of this issuer too: once any issuer is set, a CRL is selected when its
    /// issuer is one of them. Constant time, amortized.
    pub fn with_issuer(mut self, issuer: Name) -> Self {
        self.issuers.push(issuer);
        self
    }

    /// Selects the CRLs in force at `time`: published at or before it, with a next update
    /// after it. A CRL with no next update is not selected, as BC does. Constant time.
    pub fn with_date_and_time(mut self, time: Time) -> Self {
        self.date_and_time = Some(time);
        self
    }

    /// Selects the CRLs whose CRL number is at least `number`; a CRL with no CRL number is not
    /// selected. Constant time.
    pub fn with_min_crl_number(mut self, number: Asn1Integer) -> Self {
        self.min_crl_number = Some(number);
        self
    }

    /// Selects the CRLs whose CRL number is at most `number`; a CRL with no CRL number is not
    /// selected. Constant time.
    pub fn with_max_crl_number(mut self, number: Asn1Integer) -> Self {
        self.max_crl_number = Some(number);
        self
    }

    /// The issuers to select, empty when not set. Constant time.
    pub fn issuers(&self) -> &[Name] {
        &self.issuers
    }

    /// The time the CRLs must be in force at, if set. Constant time.
    pub fn date_and_time(&self) -> Option<Time> {
        self.date_and_time
    }

    /// The lowest CRL number to select, if set. Constant time.
    pub fn min_crl_number(&self) -> Option<&Asn1Integer> {
        self.min_crl_number.as_ref()
    }

    /// The highest CRL number to select, if set. Constant time.
    pub fn max_crl_number(&self) -> Option<&Asn1Integer> {
        self.max_crl_number.as_ref()
    }

    /// Whether `crl` meets every criterion set. Variable time, for public values only.
    pub fn matches(&self, crl: &X509Crl) -> bool {
        if let Some(time) = &self.date_and_time {
            let in_force = crl.this_update() <= *time
                && crl.next_update().is_some_and(|next| *time < next);
            if !in_force {
                return false;
            }
        }
        if !self.issuers.is_empty()
            && !self
                .issuers
                .iter()
                .any(|issuer| issuer.equivalent(crl.issuer()))
        {
            return false;
        }
        if self.min_crl_number.is_some() || self.max_crl_number.is_some() {
            let Some(number) = crl_number_of(crl) else {
                return false;
            };
            if self
                .min_crl_number
                .as_ref()
                .is_some_and(|min| compare_to_bound(&number, min) == Ordering::Less)
            {
                return false;
            }
            if self
                .max_crl_number
                .as_ref()
                .is_some_and(|max| compare_to_bound(&number, max) == Ordering::Greater)
            {
                return false;
            }
        }
        true
    }
}

// The CRL number of a CRL; none when it is absent or does not decode
fn crl_number_of(crl: &X509Crl) -> Option<CrlNumber> {
    let mut context = DecodingContext::new(DecodingOptions::default());
    crl.extensions()?
        .get_as::<CrlNumber>(ExtensionId::CRL_NUMBER, &mut context)
        .ok()
        .flatten()
}

// A CRL number, never negative, against a bound that may be: a negative bound is below it
fn compare_to_bound(number: &CrlNumber, bound: &Asn1Integer) -> Ordering {
    let Ok(bound) = bound.as_unsigned_bytes() else {
        return Ordering::Greater;
    };
    let Ok(number) = number.number().as_unsigned_bytes() else {
        return Ordering::Less;
    };
    let number = strip_leading_zeros(number);
    let bound = strip_leading_zeros(bound);
    number
        .len()
        .cmp(&bound.len())
        .then_with(|| number.cmp(bound))
}

fn strip_leading_zeros(magnitude: &[u8]) -> &[u8] {
    let start = magnitude
        .iter()
        .position(|&octet| octet != 0)
        .unwrap_or(magnitude.len());
    &magnitude[start..]
}
