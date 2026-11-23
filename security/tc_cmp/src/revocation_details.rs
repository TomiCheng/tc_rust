use tc_asn1::Asn1Integer;
use tc_asn1_cmp::RevDetails;
use tc_asn1_x500::Name;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationDetails {
    details: RevDetails,
}

impl From<RevDetails> for RevocationDetails {
    fn from(details: RevDetails) -> Self {
        Self { details }
    }
}

impl RevocationDetails {
    pub fn issuer(&self) -> Option<&Name> {
        self.details.cert_details().issuer()
    }

    pub fn subject(&self) -> Option<&Name> {
        self.details.cert_details().subject()
    }

    pub fn serial_number(&self) -> Option<&Asn1Integer> {
        self.details.cert_details().serial_number()
    }

    pub fn to_asn1(&self) -> &RevDetails {
        &self.details
    }

    pub fn into_asn1(self) -> RevDetails {
        self.details
    }
}
