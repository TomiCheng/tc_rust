use tc_asn1_x500::Name;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_asn1_x509::ext::NameConstraints;
use tc_x509::cert::X509Certificate;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
enum Anchor {
    Certificate(X509Certificate),
    PublicKey {
        ca: Name,
        public_key: SubjectPublicKeyInfo,
    },
}

// BC 的 TrustAnchor：信任的 CA 憑證，或 CA 的名稱加公鑰；公鑰用 SPKI 保存，驗章時才轉成金鑰
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TrustAnchor {
    anchor: Anchor,
    name_constraints: Option<NameConstraints>,
}

impl TrustAnchor {
    pub fn from_certificate(certificate: X509Certificate) -> Self {
        Self {
            anchor: Anchor::Certificate(certificate),
            name_constraints: None,
        }
    }

    pub fn from_public_key(ca: Name, public_key: SubjectPublicKeyInfo) -> Self {
        Self {
            anchor: Anchor::PublicKey { ca, public_key },
            name_constraints: None,
        }
    }

    pub fn with_name_constraints(mut self, name_constraints: NameConstraints) -> Self {
        self.name_constraints = Some(name_constraints);
        self
    }

    pub fn trusted_certificate(&self) -> Option<&X509Certificate> {
        match &self.anchor {
            Anchor::Certificate(certificate) => Some(certificate),
            Anchor::PublicKey { .. } => None,
        }
    }

    // BC 的 CA；以憑證建立時為 None，同 BC
    pub fn ca(&self) -> Option<&Name> {
        match &self.anchor {
            Anchor::Certificate(_) => None,
            Anchor::PublicKey { ca, .. } => Some(ca),
        }
    }

    // BC 的 CAPublicKey
    pub fn ca_public_key(&self) -> Option<&SubjectPublicKeyInfo> {
        match &self.anchor {
            Anchor::Certificate(_) => None,
            Anchor::PublicKey { public_key, .. } => Some(public_key),
        }
    }

    pub fn name_constraints(&self) -> Option<&NameConstraints> {
        self.name_constraints.as_ref()
    }

    // 憑證的主體或指定的 CA 名稱
    pub fn subject(&self) -> &Name {
        match &self.anchor {
            Anchor::Certificate(certificate) => certificate.subject(),
            Anchor::PublicKey { ca, .. } => ca,
        }
    }

    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        match &self.anchor {
            Anchor::Certificate(certificate) => certificate.subject_public_key_info(),
            Anchor::PublicKey { public_key, .. } => public_key,
        }
    }
}
