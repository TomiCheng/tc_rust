use std::error::Error;
use std::fmt;

use tc_asn1_x500::{
    AttributeType, AttributeValue, DirectoryString, Name, RelativeDistinguishedName,
};
use tc_asn1_x509::ext::GeneralSubtree;
use tc_asn1_x509::name::{GeneralName, OtherName};

// BC 的 PkixNameConstraintValidatorException
#[derive(Debug)]
pub struct NameConstraintError(String);

impl fmt::Display for NameConstraintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for NameConstraintError {}

type Result<T> = std::result::Result<T, NameConstraintError>;

fn fail<T>(message: impl Into<String>) -> Result<T> {
    Err(NameConstraintError(message.into()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Relation {
    Equal,
    Disjoint,
    Subsumes,
    SubsumedBy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    // local@host
    Mailbox,
    // @host
    AtHost,
    Host,
    // .domain
    Domain,
}

// BC 的 NameConstraintEmail、NameConstraintDns、NameConstraintUri 共用的形狀；相等不分大小寫
#[derive(Clone, Debug)]
struct HostName {
    kind: Kind,
    value: String,
    host: String,
}

impl PartialEq for HostName {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq_ignore_ascii_case(&other.value)
    }
}

fn strip_trailing_dot(s: &str) -> &str {
    if s.len() > 1 && s.ends_with('.') {
        &s[..s.len() - 1]
    } else {
        s
    }
}

fn check_host_labels(s: &str, host_start: usize, name_type: &str) -> Result<()> {
    if host_start >= s.len() {
        return Ok(());
    }
    if s[host_start..].starts_with('.') || s.ends_with('.') || s[host_start..].contains("..") {
        return fail(format!("{name_type} has an empty label in the host: {s}"));
    }
    Ok(())
}

// email 與 URI 的形狀：有 '@' 前綴的是信箱，以 '.' 開頭的是網域，否則是主機
fn mailbox_like(value: &str, is_constraint: bool, name_type: &str) -> Result<HostName> {
    let at = value.find('@');
    let (kind, host) = match at {
        Some(at) if at > 0 => (Kind::Mailbox, &value[at + 1..]),
        _ if value.starts_with('.') => (Kind::Domain, value),
        None => (Kind::Host, value),
        Some(_) => (Kind::AtHost, &value[1..]),
    };
    let host_start = if kind == Kind::Domain {
        usize::from(is_constraint)
    } else {
        value.len() - host.len()
    };
    check_host_labels(value, host_start, name_type)?;
    Ok(HostName {
        kind,
        value: value.to_owned(),
        host: host.to_owned(),
    })
}

fn email(value: &str, is_constraint: bool) -> Result<HostName> {
    mailbox_like(strip_trailing_dot(value), is_constraint, "rfc822Name")
}

fn uri(value: &str, is_constraint: bool) -> Result<HostName> {
    mailbox_like(
        strip_trailing_dot(value),
        is_constraint,
        "uniformResourceIdentifier",
    )
}

fn dns(value: &str, is_constraint: bool) -> Result<HostName> {
    let value = strip_trailing_dot(value);
    let host_start = usize::from(is_constraint && value.starts_with('.'));
    check_host_labels(value, host_start, "dNSName")?;
    Ok(HostName {
        kind: Kind::Domain,
        value: value.to_owned(),
        host: value.to_owned(),
    })
}

// BC 的 ExtractHostFromURL
fn host_from_url(url: &str) -> &str {
    let mut sub = url;
    if let Some(end) = sub.find(':') {
        sub = &sub[end + 1..];
    }
    if let Some(rest) = sub.strip_prefix("//") {
        sub = rest;
    }
    if let Some(end) = sub.find(['/', '?', '#']) {
        sub = &sub[..end];
    }
    if let Some(at) = sub.rfind('@') {
        sub = &sub[at + 1..];
    }
    if let Some(rest) = sub.strip_prefix('[') {
        return match rest.find(']') {
            Some(close) if close > 0 => &rest[..close],
            _ => rest,
        };
    }
    if let Some(colon) = sub.rfind(':') {
        sub = &sub[..colon];
    }
    sub
}

fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

// BC 的 WithinDomain：test_domain 是 domain 的子網域（不含 domain 本身）
fn within_domain(test_domain: &str, domain: &str) -> bool {
    let domain = domain.strip_prefix('.').unwrap_or(domain);
    let Some(boundary) = test_domain.len().checked_sub(domain.len() + 1) else {
        return false;
    };
    if boundary < 1 || test_domain.as_bytes()[boundary] != b'.' {
        return false;
    }
    eq_ignore_case(&test_domain[boundary + 1..], domain)
}

fn relate_domains(domain1: &str, domain2: &str) -> Relation {
    let off1 = usize::from(domain1.starts_with('.'));
    let off2 = usize::from(domain2.starts_with('.'));
    let (bare1, bare2) = (&domain1[off1..], &domain2[off2..]);
    match bare1.len().cmp(&bare2.len()) {
        std::cmp::Ordering::Equal => {
            if !eq_ignore_case(bare1, bare2) {
                Relation::Disjoint
            } else if off1 == off2 {
                Relation::Equal
            } else if off1 == 0 {
                Relation::Subsumes
            } else {
                Relation::SubsumedBy
            }
        }
        std::cmp::Ordering::Less => {
            if within_domain(domain2, domain1) {
                Relation::Subsumes
            } else {
                Relation::Disjoint
            }
        }
        std::cmp::Ordering::Greater => {
            if within_domain(domain1, domain2) {
                Relation::SubsumedBy
            } else {
                Relation::Disjoint
            }
        }
    }
}

fn is_particular(kind: Kind) -> bool {
    matches!(kind, Kind::Mailbox | Kind::AtHost)
}

fn when(condition: bool, relation: Relation) -> Relation {
    if condition {
        relation
    } else {
        Relation::Disjoint
    }
}

// BC 的 NameConstraintUtilities.Relate
fn relate(name1: &HostName, name2: &HostName) -> Relation {
    use Relation::*;
    if is_particular(name1.kind) {
        if is_particular(name2.kind) {
            return when(eq_ignore_case(&name1.value, &name2.value), Equal);
        }
        if name2.kind == Kind::Domain {
            return when(within_domain(&name1.host, &name2.value), SubsumedBy);
        }
        return when(eq_ignore_case(&name1.host, &name2.value), SubsumedBy);
    }
    if name1.kind == Kind::Domain {
        if is_particular(name2.kind) {
            return when(within_domain(&name2.host, &name1.value), Subsumes);
        }
        if name2.kind == Kind::Domain {
            return relate_domains(&name1.value, &name2.value);
        }
        return when(within_domain(&name2.value, &name1.value), Subsumes);
    }
    if is_particular(name2.kind) {
        return when(eq_ignore_case(&name2.host, &name1.value), Subsumes);
    }
    if name2.kind == Kind::Domain {
        return when(within_domain(&name1.value, &name2.value), SubsumedBy);
    }
    when(eq_ignore_case(&name1.value, &name2.value), Equal)
}

fn insert<T: PartialEq>(set: &mut Vec<T>, value: T) {
    if !set.contains(&value) {
        set.push(value);
    }
}

// 兩個集合各取比較窄的那個
fn intersect_with<T: PartialEq + Clone>(
    permitted: Option<&Vec<T>>,
    subtrees: Vec<T>,
    relate: impl Fn(&T, &T) -> Relation,
) -> Vec<T> {
    let mut intersect = Vec::new();
    for name in subtrees {
        match permitted {
            None => insert(&mut intersect, name),
            Some(permitted) => {
                for existing in permitted {
                    match relate(existing, &name) {
                        Relation::Equal | Relation::SubsumedBy => {
                            insert(&mut intersect, existing.clone())
                        }
                        Relation::Subsumes => insert(&mut intersect, name.clone()),
                        Relation::Disjoint => {}
                    }
                }
            }
        }
    }
    intersect
}

// BC 的 Union：已被涵蓋就不變，涵蓋了舊的就取代它們
fn union_with<T: PartialEq>(
    excluded: &mut Option<Vec<T>>,
    name: T,
    relate: impl Fn(&T, &T) -> Relation,
) {
    let Some(set) = excluded else {
        *excluded = Some(vec![name]);
        return;
    };
    let mut dropped = Vec::new();
    for (index, existing) in set.iter().enumerate() {
        match relate(existing, &name) {
            Relation::Equal | Relation::Subsumes => return,
            Relation::SubsumedBy => dropped.push(index),
            Relation::Disjoint => {}
        }
    }
    for index in dropped.into_iter().rev() {
        set.remove(index);
    }
    insert(set, name);
}

fn email_constrained(constraint: &HostName, email: &HostName) -> bool {
    match constraint.kind {
        Kind::Mailbox => eq_ignore_case(&email.value, &constraint.value),
        Kind::AtHost => eq_ignore_case(&email.host, &constraint.host),
        Kind::Domain => within_domain(&email.host, &constraint.value),
        Kind::Host => eq_ignore_case(&email.host, &constraint.value),
    }
}

fn uri_constrained(constraint: &HostName, host: &HostName) -> bool {
    if constraint.kind == Kind::Domain {
        within_domain(&host.value, &constraint.value)
    } else {
        eq_ignore_case(&host.value, &constraint.value)
    }
}

fn dns_constrained(constraint: &HostName, name: &HostName) -> bool {
    matches!(
        relate(name, constraint),
        Relation::Equal | Relation::SubsumedBy
    )
}

// BC 的 NameConstraintDN：以 RDN 前綴判斷子樹
fn relate_dn(dn1: &Name, dn2: &Name) -> Relation {
    let (rdns1, rdns2) = (dn1.rdns(), dn2.rdns());
    if rdns1.is_empty() || rdns2.is_empty() {
        return Relation::Disjoint;
    }
    if rdns1.iter().zip(rdns2).any(|(a, b)| !a.equivalent(b)) {
        return Relation::Disjoint;
    }
    match rdns1.len().cmp(&rdns2.len()) {
        std::cmp::Ordering::Equal => Relation::Equal,
        std::cmp::Ordering::Less => Relation::Subsumes,
        std::cmp::Ordering::Greater => Relation::SubsumedBy,
    }
}

fn within_dn_subtree(dn: &Name, subtree: &Name) -> bool {
    let (rdns, subtree) = (dn.rdns(), subtree.rdns());
    !subtree.is_empty()
        && subtree.len() <= rdns.len()
        && subtree.iter().zip(rdns).all(|(a, b)| a.equivalent(b))
}

// GSMA SGP.22：子樹的每個 RDN 都要在名稱裡某處出現，serialNumber 只比前綴
fn within_dn_subtree_sgp22(dn: &Name, subtree: &Name) -> bool {
    let (rdns, subtree) = (dn.rdns(), subtree.rdns());
    !subtree.is_empty()
        && subtree.len() <= rdns.len()
        && subtree
            .iter()
            .all(|wanted| rdns.iter().any(|rdn| rdn_matches_sgp22(wanted, rdn)))
}

fn rdn_matches_sgp22(subtree: &RelativeDistinguishedName, rdn: &RelativeDistinguishedName) -> bool {
    let (wanted, found) = (subtree.attributes(), rdn.attributes());
    if wanted.len() != found.len() || wanted.is_empty() {
        return false;
    }
    if wanted[0].attribute_type() != found[0].attribute_type() {
        return false;
    }
    if wanted.len() == 1 && *wanted[0].attribute_type() == AttributeType::SERIAL_NUMBER.oid() {
        if let AttributeValue::DirectoryString(DirectoryString::PrintableString(found)) =
            found[0].value()
        {
            let prefix = match wanted[0].value() {
                AttributeValue::DirectoryString(text) => text.as_str(),
                AttributeValue::Ia5String(text) => Some(text.as_str()),
                _ => None,
            };
            if let Some(prefix) = prefix {
                return found.as_str().starts_with(prefix);
            }
        }
    }
    subtree.equivalent(rdn)
}

// BC 的 NameConstraintIPRange：位址加連續遮罩，主機位元清零；IPv4-mapped IPv6 收成 IPv4
#[derive(Clone, Debug, PartialEq)]
struct IpRange {
    bytes: Vec<u8>,
    prefix: usize,
}

fn is_ipv4_mapped(ip: &[u8], off: usize) -> bool {
    ip[off..off + 10].iter().all(|&b| b == 0) && ip[off + 10] == 0xff && ip[off + 11] == 0xff
}

fn is_contiguous_mask(mask: &[u8]) -> bool {
    let mut i = 0;
    while i < mask.len() && mask[i] == 0xff {
        i += 1;
    }
    if i < mask.len() {
        let c = !mask[i];
        if c & c.wrapping_add(1) != 0 {
            return false;
        }
        if mask[i + 1..].iter().any(|&b| b != 0) {
            return false;
        }
    }
    true
}

fn prefix_length(mask: &[u8]) -> usize {
    (0..mask.len() * 8)
        .find(|&bit| mask[bit >> 3] & (0x80 >> (bit & 7)) == 0)
        .unwrap_or(mask.len() * 8)
}

fn ip_range(octets: &[u8]) -> Result<IpRange> {
    let length = octets.len();
    if length != 8 && length != 32 {
        return fail(format!("iPAddress constraint has invalid length: {length}"));
    }
    let half = length / 2;
    if !is_contiguous_mask(&octets[half..]) {
        return fail("iPAddress constraint has a non-contiguous subnet mask");
    }
    let mut bytes = octets.to_vec();
    if length == 32 && is_ipv4_mapped(&bytes, 0) && bytes[16..28].iter().all(|&b| b == 0xff) {
        bytes = [&octets[12..16], &octets[28..32]].concat();
    }
    let half = bytes.len() / 2;
    for i in 0..half {
        bytes[i] &= bytes[half + i];
    }
    let prefix = prefix_length(&bytes[half..]);
    Ok(IpRange { bytes, prefix })
}

fn ip_address(octets: &[u8]) -> Result<Vec<u8>> {
    let bytes = if octets.len() == 16 && is_ipv4_mapped(octets, 0) {
        octets[12..].to_vec()
    } else {
        octets.to_vec()
    };
    if bytes.len() != 4 && bytes.len() != 16 {
        return fail(format!(
            "iPAddress name has invalid length: {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn ip_constrained(constraint: &IpRange, ip: &[u8]) -> bool {
    let length = ip.len();
    if length != constraint.bytes.len() / 2 {
        return false;
    }
    (0..length).all(|i| {
        let mask = constraint.bytes[length + i];
        ip[i] & mask == constraint.bytes[i] & mask
    })
}

fn relate_ip(range1: &IpRange, range2: &IpRange) -> Relation {
    let (b1, b2) = (&range1.bytes, &range2.bytes);
    if b1.len() != b2.len() {
        return Relation::Disjoint;
    }
    let half = b1.len() / 2;
    for i in 0..half {
        let common = b1[half + i] & b2[half + i];
        if (b1[i] ^ b2[i]) & common != 0 {
            return Relation::Disjoint;
        }
    }
    match range1.prefix.cmp(&range2.prefix) {
        std::cmp::Ordering::Equal => Relation::Equal,
        std::cmp::Ordering::Less => Relation::Subsumes,
        std::cmp::Ordering::Greater => Relation::SubsumedBy,
    }
}

fn relate_other_name(a: &OtherName, b: &OtherName) -> Relation {
    if a == b {
        Relation::Equal
    } else {
        Relation::Disjoint
    }
}

// BC 的 PkixNameConstraintValidator：permitted 為 None 是不受限，Some(空) 是什麼都不允許；
// excluded 為 None 是還沒有排除任何子樹
#[derive(Clone, Debug, Default)]
pub(crate) struct NameConstraintValidator {
    excluded_dn: Option<Vec<Name>>,
    excluded_dns: Option<Vec<HostName>>,
    excluded_email: Option<Vec<HostName>>,
    excluded_uri: Option<Vec<HostName>>,
    excluded_ip: Option<Vec<IpRange>>,
    excluded_other_name: Option<Vec<OtherName>>,
    permitted_dn: Option<Vec<Name>>,
    permitted_dns: Option<Vec<HostName>>,
    permitted_email: Option<Vec<HostName>>,
    permitted_uri: Option<Vec<HostName>>,
    permitted_ip: Option<Vec<IpRange>>,
    permitted_other_name: Option<Vec<OtherName>>,
}

impl NameConstraintValidator {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn check_dn(&self, dn: &Name) -> Result<()> {
        check_dn(
            self.permitted_dn.as_ref(),
            self.excluded_dn.as_ref(),
            dn,
            false,
        )
    }

    pub(crate) fn check_dn_sgp22(&self, dn: &Name) -> Result<()> {
        check_dn(
            self.permitted_dn.as_ref(),
            self.excluded_dn.as_ref(),
            dn,
            true,
        )
    }

    pub(crate) fn check_email(&self, address: &str) -> Result<()> {
        check_email(
            self.permitted_email.as_ref(),
            self.excluded_email.as_ref(),
            address,
        )
    }

    pub(crate) fn check_name(&self, name: &GeneralName) -> Result<()> {
        match name {
            GeneralName::OtherName(other) => {
                if let Some(permitted) = &self.permitted_other_name {
                    if !permitted.contains(other) {
                        return fail("Subject OtherName is not from a permitted subtree.");
                    }
                }
                if let Some(excluded) = &self.excluded_other_name {
                    if excluded.contains(other) {
                        return fail("OtherName is from an excluded subtree.");
                    }
                }
                Ok(())
            }
            GeneralName::Rfc822Name(address) => check_email(
                self.permitted_email.as_ref(),
                self.excluded_email.as_ref(),
                address.as_str(),
            ),
            GeneralName::DnsName(name) => {
                let name = name.as_str();
                let check_permitted = self
                    .permitted_dns
                    .as_ref()
                    .is_some_and(|p| !(name.is_empty() && p.is_empty()));
                let check_excluded = self.excluded_dns.is_some();
                if !check_permitted && !check_excluded {
                    return Ok(());
                }
                let name = dns(name, false)?;
                if check_permitted
                    && !self
                        .permitted_dns
                        .iter()
                        .flatten()
                        .any(|c| dns_constrained(c, &name))
                {
                    return fail("DNS is not from a permitted subtree.");
                }
                if self
                    .excluded_dns
                    .iter()
                    .flatten()
                    .any(|c| dns_constrained(c, &name))
                {
                    return fail("DNS is from an excluded subtree.");
                }
                Ok(())
            }
            GeneralName::DirectoryName(dn) => check_dn(
                self.permitted_dn.as_ref(),
                self.excluded_dn.as_ref(),
                dn,
                false,
            ),
            GeneralName::Uri(text) => {
                let text = text.as_str();
                let check_permitted = self
                    .permitted_uri
                    .as_ref()
                    .is_some_and(|p| !(text.is_empty() && p.is_empty()));
                let check_excluded = self.excluded_uri.is_some();
                if !check_permitted && !check_excluded {
                    return Ok(());
                }
                let host = uri(host_from_url(text), false)?;
                if check_permitted
                    && !self
                        .permitted_uri
                        .iter()
                        .flatten()
                        .any(|c| uri_constrained(c, &host))
                {
                    return fail("URI is not from a permitted subtree.");
                }
                if self
                    .excluded_uri
                    .iter()
                    .flatten()
                    .any(|c| uri_constrained(c, &host))
                {
                    return fail("URI is from an excluded subtree.");
                }
                Ok(())
            }
            GeneralName::IpAddress(octets) => {
                if self.permitted_ip.is_none() && self.excluded_ip.is_none() {
                    return Ok(());
                }
                let ip = ip_address(octets.as_bytes())?;
                if let Some(permitted) = &self.permitted_ip {
                    if !permitted.iter().any(|c| ip_constrained(c, &ip)) {
                        return fail("IP is not from a permitted subtree.");
                    }
                }
                if self
                    .excluded_ip
                    .iter()
                    .flatten()
                    .any(|c| ip_constrained(c, &ip))
                {
                    return fail("IP is from an excluded subtree.");
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    // BC 的 IntersectPermittedSubtree(Asn1Sequence)：依名稱種類分組，各自取交集
    pub(crate) fn intersect_permitted_subtree(
        &mut self,
        subtrees: &[GeneralSubtree],
    ) -> Result<()> {
        let mut tags: Vec<u8> = Vec::new();
        for subtree in subtrees {
            let tag = tag_of(subtree.base());
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
        tags.sort_unstable();
        for tag in tags {
            let group = subtrees
                .iter()
                .filter(|s| tag_of(s.base()) == tag)
                .map(GeneralSubtree::base);
            match tag {
                0 => {
                    let names = group
                        .filter_map(|name| match name {
                            GeneralName::OtherName(other) => Some(other.clone()),
                            _ => None,
                        })
                        .collect();
                    self.permitted_other_name = Some(intersect_with(
                        self.permitted_other_name.as_ref(),
                        names,
                        relate_other_name,
                    ));
                }
                1 => {
                    let names = group
                        .map(|n| email(ia5(n), true))
                        .collect::<Result<Vec<_>>>()?;
                    self.permitted_email =
                        Some(intersect_with(self.permitted_email.as_ref(), names, relate));
                }
                2 => {
                    let names = group
                        .map(|n| dns(ia5(n), true))
                        .collect::<Result<Vec<_>>>()?;
                    self.permitted_dns =
                        Some(intersect_with(self.permitted_dns.as_ref(), names, relate));
                }
                4 => {
                    let names = group
                        .filter_map(|name| match name {
                            GeneralName::DirectoryName(dn) => Some(dn.clone()),
                            _ => None,
                        })
                        .collect();
                    self.permitted_dn =
                        Some(intersect_with(self.permitted_dn.as_ref(), names, relate_dn));
                }
                6 => {
                    let names = group
                        .map(|n| uri(ia5(n), true))
                        .collect::<Result<Vec<_>>>()?;
                    self.permitted_uri =
                        Some(intersect_with(self.permitted_uri.as_ref(), names, relate));
                }
                7 => {
                    let names = group
                        .map(|name| match name {
                            GeneralName::IpAddress(octets) => ip_range(octets.as_bytes()),
                            _ => unreachable!("grouped by tag"),
                        })
                        .collect::<Result<Vec<_>>>()?;
                    self.permitted_ip =
                        Some(intersect_with(self.permitted_ip.as_ref(), names, relate_ip));
                }
                _ => return fail(format!("Unknown tag encountered: {tag}")),
            }
        }
        Ok(())
    }

    pub(crate) fn add_excluded_subtree(&mut self, subtree: &GeneralSubtree) -> Result<()> {
        match subtree.base() {
            GeneralName::OtherName(other) => union_with(
                &mut self.excluded_other_name,
                other.clone(),
                relate_other_name,
            ),
            GeneralName::Rfc822Name(text) => union_with(
                &mut self.excluded_email,
                email(text.as_str(), true)?,
                relate,
            ),
            GeneralName::DnsName(text) => {
                union_with(&mut self.excluded_dns, dns(text.as_str(), true)?, relate)
            }
            GeneralName::DirectoryName(dn) => {
                union_with(&mut self.excluded_dn, dn.clone(), relate_dn)
            }
            GeneralName::Uri(text) => {
                union_with(&mut self.excluded_uri, uri(text.as_str(), true)?, relate)
            }
            GeneralName::IpAddress(octets) => union_with(
                &mut self.excluded_ip,
                ip_range(octets.as_bytes())?,
                relate_ip,
            ),
            other => return fail(format!("Unknown tag encountered: {}", tag_of(other))),
        }
        Ok(())
    }
}

fn tag_of(name: &GeneralName) -> u8 {
    match name {
        GeneralName::OtherName(_) => 0,
        GeneralName::Rfc822Name(_) => 1,
        GeneralName::DnsName(_) => 2,
        GeneralName::X400Address(_) => 3,
        GeneralName::DirectoryName(_) => 4,
        GeneralName::EdiPartyName(_) => 5,
        GeneralName::Uri(_) => 6,
        GeneralName::IpAddress(_) => 7,
        GeneralName::RegisteredId(_) => 8,
        _ => u8::MAX,
    }
}

fn ia5(name: &GeneralName) -> &str {
    match name {
        GeneralName::Rfc822Name(text) | GeneralName::DnsName(text) | GeneralName::Uri(text) => {
            text.as_str()
        }
        _ => "",
    }
}

fn check_dn(
    permitted: Option<&Vec<Name>>,
    excluded: Option<&Vec<Name>>,
    dn: &Name,
    sgp22: bool,
) -> Result<()> {
    let check_permitted = permitted.is_some_and(|p| !(dn.rdns().is_empty() && p.is_empty()));
    let within = |subtree: &Name| {
        if sgp22 {
            within_dn_subtree_sgp22(dn, subtree)
        } else {
            within_dn_subtree(dn, subtree)
        }
    };
    if check_permitted && !permitted.into_iter().flatten().any(|s| within(s)) {
        return fail("Subject distinguished name is not from a permitted subtree");
    }
    if excluded.into_iter().flatten().any(|s| within(s)) {
        return fail("Subject distinguished name is from an excluded subtree");
    }
    Ok(())
}

fn check_email(
    permitted: Option<&Vec<HostName>>,
    excluded: Option<&Vec<HostName>>,
    address: &str,
) -> Result<()> {
    let check_permitted = permitted.is_some_and(|p| !(address.is_empty() && p.is_empty()));
    if !check_permitted && excluded.is_none() {
        return Ok(());
    }
    // 一個以上的 '@' 可能被拆成錯的主機而避開限制，同 BC 預設拒絕
    if address.find('@') != address.rfind('@') {
        return fail("Subject email address is ambiguous (multiple '@').");
    }
    let name = email(address, false)?;
    if check_permitted
        && !permitted
            .into_iter()
            .flatten()
            .any(|c| email_constrained(c, &name))
    {
        return fail("Subject email address is not from a permitted subtree.");
    }
    if excluded
        .into_iter()
        .flatten()
        .any(|c| email_constrained(c, &name))
    {
        return fail("Email address is from an excluded subtree.");
    }
    Ok(())
}
