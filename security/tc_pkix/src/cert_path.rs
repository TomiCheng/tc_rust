use tc_x509::cert::X509Certificate;

// BC 的 PkixCertPath：終端憑證在前，往信任錨的方向排；給的順序不對時照 BC 的 SortCerts 排好，
// 排不出唯一一條鏈就保持原樣
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PkixCertPath {
    certificates: Vec<X509Certificate>,
}

impl PkixCertPath {
    pub fn new(certificates: Vec<X509Certificate>) -> Self {
        Self {
            certificates: sort(certificates),
        }
    }

    pub fn certificates(&self) -> &[X509Certificate] {
        &self.certificates
    }

    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }
}

fn is_sorted(certificates: &[X509Certificate]) -> bool {
    certificates
        .windows(2)
        .all(|pair| pair[0].issuer().equivalent(pair[1].subject()))
}

fn sort(certificates: Vec<X509Certificate>) -> Vec<X509Certificate> {
    if certificates.len() < 2 || is_sorted(&certificates) {
        return certificates;
    }
    let original = certificates.clone();
    // 不是任何一張憑證簽發者的，是終端憑證；只能有一張
    let mut rest = certificates;
    let mut sorted = Vec::with_capacity(rest.len());
    let mut i = 0;
    while i < rest.len() {
        let subject = rest[i].subject();
        if original.iter().any(|c| c.issuer().equivalent(subject)) {
            i += 1;
        } else {
            sorted.push(rest.remove(i));
        }
    }
    if sorted.len() > 1 {
        return original;
    }
    let mut i = 0;
    while i < sorted.len() {
        let issuer = sorted[i].issuer().clone();
        if let Some(j) = rest.iter().position(|c| issuer.equivalent(c.subject())) {
            sorted.push(rest.remove(j));
        }
        i += 1;
    }
    if !rest.is_empty() {
        return original;
    }
    sorted
}
