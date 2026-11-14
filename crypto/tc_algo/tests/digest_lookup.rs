use std::sync::{Arc, RwLock};

use tc_algo::digest::{Digest, DigestEntry, TryDigest};
use tc_algo::{
    Algo, AlgoBuilder, AlgoError, DefaultAlgoBuilder, DefaultAlgoContext, EntryBase, ErrorKind,
    ListPolicy, Policy,
};
use tc_asn1::Asn1Oid;

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    mark: u8,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl DigestEntry for Row {
    fn create(&self) -> Box<dyn Digest> {
        Box::new(Marked(self.mark))
    }
}

// Its hash is the mark of the row that created it, to tell which row a lookup found
struct Marked(u8);

impl TryDigest for Marked {
    type Error = AlgoError;

    fn digest_size(&self) -> usize {
        1
    }

    fn byte_length(&self) -> usize {
        1
    }

    fn try_update(&mut self, _input: &[u8]) -> Result<(), AlgoError> {
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        let first = output
            .first_mut()
            .ok_or(AlgoError::new(ErrorKind::DataLength))?;
        *first = self.0;
        Ok(1)
    }

    fn try_reset(&mut self) -> Result<(), AlgoError> {
        Ok(())
    }
}

impl Digest for Marked {}

fn row(name: &'static str, aliases: &[&str], oids: &[&str], mark: u8) -> Box<dyn DigestEntry> {
    Box::new(Row {
        name,
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        oids: oids.iter().map(|dotted| oid(dotted)).collect(),
        mark,
    })
}

fn oid(dotted: &str) -> Asn1Oid {
    dotted.parse().expect("a valid OID")
}

type Rows = fn(&DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>>;

fn older(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    vec![row("TEST-DIGEST", &["TESTD"], &["1.2.3.4"], 1)]
}

fn newer(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    vec![row("TEST-DIGEST", &[], &["1.2.3.4"], 2)]
}

fn other_name_same_alias(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    vec![row("OTHER-DIGEST", &["TEST-DIGEST"], &[], 3)]
}

fn several(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    vec![
        row("TEST-DIGEST", &[], &[], 5),
        row("OTHER-TEST-DIGEST", &[], &[], 6),
    ]
}

fn algo_with(rows: &[Rows]) -> Box<dyn Algo> {
    let mut builder = DefaultAlgoBuilder::default();
    for row in rows {
        builder.reg_digest(*row);
    }
    builder.build()
}

fn mark_by_name(algo: &dyn Algo, name: &str) -> Option<Vec<u8>> {
    algo.digest().get_by_name(name).ok()?.finalize().ok()
}

#[test]
fn a_digest_is_found_by_its_name_or_alias_whatever_their_case() {
    let algo = algo_with(&[older]);
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-DIGEST"), Some(vec![1]));
    assert_eq!(mark_by_name(algo.as_ref(), "test-digest"), Some(vec![1]));
    assert_eq!(mark_by_name(algo.as_ref(), "TestD"), Some(vec![1]));
}

#[test]
fn a_digest_is_found_by_its_oid() {
    let algo = algo_with(&[older]);
    let mut digest = algo.digest().get_by_oid(&oid("1.2.3.4")).unwrap();
    assert_eq!(digest.finalize().unwrap(), [1]);
}

#[test]
fn an_unknown_name_or_oid_is_reported_as_unknown_digest() {
    let algo = algo_with(&[older]);
    assert_eq!(
        algo.digest()
            .get_by_name("NO-SUCH-DIGEST")
            .err()
            .unwrap()
            .kind(),
        ErrorKind::UnknownDigest
    );
    assert_eq!(
        algo.digest()
            .get_by_oid(&oid("1.2.3.5"))
            .err()
            .unwrap()
            .kind(),
        ErrorKind::UnknownDigest
    );
}

#[test]
fn the_last_registered_digest_is_the_one_found_by_a_shared_name_or_oid() {
    let algo = algo_with(&[older, newer]);
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-DIGEST"), Some(vec![2]));
    let mut digest = algo.digest().get_by_oid(&oid("1.2.3.4")).unwrap();
    assert_eq!(digest.finalize().unwrap(), [2]);
}

#[test]
fn the_older_digest_is_still_found_by_what_the_newer_one_does_not_claim() {
    let algo = algo_with(&[older, newer]);
    assert_eq!(mark_by_name(algo.as_ref(), "TESTD"), Some(vec![1]));
}

#[test]
fn an_alias_of_a_later_digest_takes_the_name_of_an_earlier_one() {
    let algo = algo_with(&[older, other_name_same_alias]);
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-DIGEST"), Some(vec![3]));
}

#[test]
fn the_list_has_the_last_registered_first_and_keeps_the_replaced_digest() {
    let algo = algo_with(&[older, newer]);
    let marks: Vec<Vec<u8>> = algo
        .digest()
        .algorithms()
        .filter(|entry| entry.name() == "TEST-DIGEST")
        .map(|entry| entry.create().finalize().unwrap())
        .collect();
    assert_eq!(marks, [[2], [1]]);
}

#[test]
fn a_function_registers_all_its_digests_together_and_in_the_order_it_returns_them() {
    let algo = algo_with(&[older, several]);
    let marks: Vec<Vec<u8>> = algo
        .digest()
        .algorithms()
        .filter(|entry| entry.name().contains("TEST-DIGEST"))
        .map(|entry| entry.create().finalize().unwrap())
        .collect();
    assert_eq!(marks, [[5], [6], [1]]);

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-DIGEST"), Some(vec![5]));
    assert_eq!(
        mark_by_name(algo.as_ref(), "OTHER-TEST-DIGEST"),
        Some(vec![6])
    );
}

#[test]
fn the_helpers_calculate_with_the_digest_a_lookup_finds() {
    let algo = algo_with(&[older, newer]);
    let digests = algo.digest();
    assert_eq!(digests.calculate_by_name("TEST-DIGEST", b"").unwrap(), [2]);
    assert_eq!(digests.calculate_by_oid(&oid("1.2.3.4"), b"").unwrap(), [2]);
}

#[test]
fn the_helpers_report_an_unknown_digest() {
    let algo = algo_with(&[]);
    let digests = algo.digest();

    let by_name = digests.calculate_by_name("NO-SUCH-DIGEST", b"");
    assert_eq!(by_name.unwrap_err().kind(), ErrorKind::UnknownDigest);

    let by_oid = digests.calculate_by_oid(&oid("1.2.3.5"), b"");
    assert_eq!(by_oid.unwrap_err().kind(), ErrorKind::UnknownDigest);
}

fn unrelated(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    vec![row("UNRELATED-DIGEST", &[], &[], 4)]
}

fn algo_with_policy(rows: &[Rows], policy: impl Policy + 'static) -> Box<dyn Algo> {
    let mut builder = DefaultAlgoBuilder::default();
    for row in rows {
        builder.reg_digest(*row);
    }
    builder.set_policy(policy);
    builder.build()
}

fn is_listed(algo: &dyn Algo, name: &str) -> bool {
    algo.digest().algorithms().any(|entry| entry.name() == name)
}

#[test]
fn a_policy_leaves_a_digest_out_of_the_list_but_a_lookup_still_finds_it() {
    let policy = ListPolicy::new().with_deny(["TEST-DIGEST"]);
    let algo = algo_with_policy(&[older, newer, unrelated], policy);

    assert!(!is_listed(algo.as_ref(), "TEST-DIGEST"));
    assert!(is_listed(algo.as_ref(), "UNRELATED-DIGEST"));

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-DIGEST"), Some(vec![2]));
    let mut digest = algo.digest().get_by_oid(&oid("1.2.3.4")).unwrap();
    assert_eq!(digest.finalize().unwrap(), [2]);
}

// What a policy over a watched file does: the file can change while the Algo is in use
#[derive(Clone, Default)]
struct WatchedDenyList(Arc<RwLock<Vec<String>>>);

impl Policy for WatchedDenyList {
    fn filter(&self, entry: &dyn EntryBase) -> bool {
        let denied = self.0.read().unwrap();
        !denied.iter().any(|name| name == entry.name())
    }
}

#[test]
fn a_policy_that_changes_its_answer_changes_the_next_list() {
    let denied = WatchedDenyList::default();
    let algo = algo_with_policy(&[older], denied.clone());
    assert!(is_listed(algo.as_ref(), "TEST-DIGEST"));

    denied.0.write().unwrap().push("TEST-DIGEST".to_string());
    assert!(!is_listed(algo.as_ref(), "TEST-DIGEST"));

    denied.0.write().unwrap().clear();
    assert!(is_listed(algo.as_ref(), "TEST-DIGEST"));
}

struct DenyOid(&'static str);

impl Policy for DenyOid {
    fn filter(&self, entry: &dyn EntryBase) -> bool {
        !entry.oids().contains(&oid(self.0))
    }
}

#[test]
fn a_policy_can_tell_a_digest_by_its_alias_or_its_oid() {
    let by_alias = ListPolicy::new().with_deny(["TESTD"]);
    let algo = algo_with_policy(&[older], by_alias);
    assert!(!is_listed(algo.as_ref(), "TEST-DIGEST"));

    let algo = algo_with_policy(&[older], DenyOid("1.2.3.4"));
    assert!(!is_listed(algo.as_ref(), "TEST-DIGEST"));
}

#[cfg(feature = "sha256")]
mod sha256 {
    use super::*;

    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn my_sha256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
        vec![row("SHA-256", &[], &[], 9)]
    }

    // FIPS 180-4's example for the message "abc"
    #[test]
    fn the_built_in_digest_gives_the_standard_hash_by_its_name_alias_and_oid() {
        let algo = algo_with(&[]);
        let digests = algo.digest();

        let by_name = digests.calculate_by_name("SHA-256", b"abc").unwrap();
        assert_eq!(hex(&by_name), ABC);

        let by_alias = digests.calculate_by_name("sha256", b"abc").unwrap();
        assert_eq!(hex(&by_alias), ABC);

        let by_oid = digests
            .calculate_by_oid(&oid("2.16.840.1.101.3.4.2.1"), b"abc")
            .unwrap();
        assert_eq!(hex(&by_oid), ABC);
    }

    #[test]
    fn a_registered_digest_replaces_the_built_in_one_of_the_same_name() {
        let algo = algo_with(&[my_sha256]);
        assert_eq!(mark_by_name(algo.as_ref(), "SHA-256"), Some(vec![9]));

        // It claims only the name, so the rest still finds the built-in one
        let by_alias = algo.digest().calculate_by_name("SHA256", b"abc").unwrap();
        assert_eq!(hex(&by_alias), ABC);
    }
}
