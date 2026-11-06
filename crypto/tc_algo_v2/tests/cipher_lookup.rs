use std::sync::{Arc, RwLock};

use tc_algo_v2::cipher::{Cipher, CipherDirection, CipherEntry};
use tc_algo_v2::{
    Algo, AlgoBuilder, AlgoError, DefaultAlgoBuilder, DefaultAlgoContext, EntryBase, ErrorKind,
    ListPolicy, Params, Policy,
};
use tc_asn1::Asn1Oid;

struct NoParams;

impl Params for NoParams {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

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

impl CipherEntry for Row {
    fn create(&self) -> Box<dyn Cipher> {
        Box::new(Marked {
            mark: self.mark,
            direction: None,
        })
    }
}

// Copies its input, then ends with the mark of the row that created it and the direction it was
// given, to tell which row a lookup found and what a helper passed on
struct Marked {
    mark: u8,
    direction: Option<CipherDirection>,
}

const ENCRYPTED: u8 = 0xE;
const DECRYPTED: u8 = 0xD;

impl Cipher for Marked {
    fn init(&mut self, direction: CipherDirection, _params: &dyn Params) -> Result<(), AlgoError> {
        self.direction = Some(direction);
        Ok(())
    }

    fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        Ok(input.to_vec())
    }

    fn finalize(&mut self) -> Result<Vec<u8>, AlgoError> {
        let direction = match self.direction {
            Some(CipherDirection::Encrypt) => ENCRYPTED,
            Some(CipherDirection::Decrypt) => DECRYPTED,
            None => 0,
        };
        Ok(vec![self.mark, direction])
    }
}

fn row(name: &'static str, aliases: &[&str], oids: &[&str], mark: u8) -> Box<dyn CipherEntry> {
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

type Rows = fn(&DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>>;

fn older(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("TEST-CIPHER", &["TESTC"], &["1.2.3.4"], 1)]
}

fn newer(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("TEST-CIPHER", &[], &["1.2.3.4"], 2)]
}

fn unrelated(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("UNRELATED-CIPHER", &[], &[], 3)]
}

fn several(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![
        row("TEST-CIPHER", &[], &[], 4),
        row("OTHER-TEST-CIPHER", &[], &[], 5),
    ]
}

fn builder_with(rows: &[Rows]) -> DefaultAlgoBuilder {
    let mut builder = DefaultAlgoBuilder::default();
    for row in rows {
        builder.reg_cipher(*row);
    }
    builder
}

fn algo_with(rows: &[Rows]) -> Box<dyn Algo> {
    builder_with(rows).build()
}

fn algo_with_policy(rows: &[Rows], policy: impl Policy + 'static) -> Box<dyn Algo> {
    let mut builder = builder_with(rows);
    builder.set_policy(policy);
    builder.build()
}

fn mark_of(mut cipher: Box<dyn Cipher>) -> u8 {
    cipher.finalize().unwrap()[0]
}

fn mark_by_name(algo: &dyn Algo, name: &str) -> Option<u8> {
    Some(mark_of(algo.cipher().get_by_name(name).ok()?))
}

fn mark_by_oid(algo: &dyn Algo, dotted: &str) -> Option<u8> {
    Some(mark_of(algo.cipher().get_by_oid(&oid(dotted)).ok()?))
}

fn is_listed(algo: &dyn Algo, name: &str) -> bool {
    algo.cipher().algorithms().any(|entry| entry.name() == name)
}

#[test]
fn a_cipher_is_found_by_its_name_or_alias_whatever_their_case() {
    let algo = algo_with(&[older]);
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-CIPHER"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "test-cipher"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "TestC"), Some(1));
}

#[test]
fn a_cipher_is_found_by_its_oid() {
    let algo = algo_with(&[older]);
    assert_eq!(mark_by_oid(algo.as_ref(), "1.2.3.4"), Some(1));
}

#[test]
fn an_unknown_name_or_oid_is_reported_as_unknown_cipher() {
    let algo = algo_with(&[older]);
    assert_eq!(
        algo.cipher()
            .get_by_name("NO-SUCH-CIPHER")
            .err()
            .unwrap()
            .kind(),
        ErrorKind::UnknownCipher
    );
    assert_eq!(
        algo.cipher()
            .get_by_oid(&oid("1.2.3.5"))
            .err()
            .unwrap()
            .kind(),
        ErrorKind::UnknownCipher
    );
}

#[test]
fn the_last_registered_cipher_is_the_one_found_by_a_shared_name_or_oid() {
    let algo = algo_with(&[older, newer]);
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-CIPHER"), Some(2));
    assert_eq!(mark_by_oid(algo.as_ref(), "1.2.3.4"), Some(2));
}

#[test]
fn the_list_has_the_last_registered_first_and_keeps_the_replaced_cipher() {
    let algo = algo_with(&[older, newer]);
    let marks: Vec<u8> = algo
        .cipher()
        .algorithms()
        .filter(|entry| entry.name() == "TEST-CIPHER")
        .map(|entry| mark_of(entry.create()))
        .collect();
    assert_eq!(marks, [2, 1]);
}

#[test]
fn a_function_registers_all_its_ciphers_together_and_in_the_order_it_returns_them() {
    let algo = algo_with(&[older, several]);
    let marks: Vec<u8> = algo
        .cipher()
        .algorithms()
        .filter(|entry| entry.name().contains("TEST-CIPHER"))
        .map(|entry| mark_of(entry.create()))
        .collect();
    assert_eq!(marks, [4, 5, 1]);

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-CIPHER"), Some(4));
    assert_eq!(mark_by_name(algo.as_ref(), "OTHER-TEST-CIPHER"), Some(5));
}

#[test]
fn the_helpers_init_the_cipher_with_their_direction_and_join_what_it_returns() {
    let algo = algo_with(&[older]);
    let ciphers = algo.cipher();
    let cipher_oid = oid("1.2.3.4");

    assert_eq!(
        ciphers
            .encrypt_by_name("TEST-CIPHER", &NoParams, b"hi")
            .unwrap(),
        [b'h', b'i', 1, ENCRYPTED]
    );
    assert_eq!(
        ciphers
            .decrypt_by_name("TEST-CIPHER", &NoParams, b"hi")
            .unwrap(),
        [b'h', b'i', 1, DECRYPTED]
    );
    assert_eq!(
        ciphers
            .encrypt_by_oid(&cipher_oid, &NoParams, b"hi")
            .unwrap(),
        [b'h', b'i', 1, ENCRYPTED]
    );
    assert_eq!(
        ciphers
            .decrypt_by_oid(&cipher_oid, &NoParams, b"hi")
            .unwrap(),
        [b'h', b'i', 1, DECRYPTED]
    );
}

#[test]
fn the_helpers_report_an_unknown_cipher() {
    let algo = algo_with(&[]);
    let ciphers = algo.cipher();

    let by_name = ciphers.encrypt_by_name("NO-SUCH-CIPHER", &NoParams, b"");
    assert_eq!(by_name.unwrap_err().kind(), ErrorKind::UnknownCipher);

    let by_oid = ciphers.decrypt_by_oid(&oid("1.2.3.5"), &NoParams, b"");
    assert_eq!(by_oid.unwrap_err().kind(), ErrorKind::UnknownCipher);
}

#[test]
fn a_policy_leaves_a_cipher_out_of_the_list_but_a_lookup_still_finds_it() {
    let policy = ListPolicy::new().with_deny(["TEST-CIPHER"]);
    let algo = algo_with_policy(&[older, newer, unrelated], policy);

    assert!(!is_listed(algo.as_ref(), "TEST-CIPHER"));
    assert!(is_listed(algo.as_ref(), "UNRELATED-CIPHER"));

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-CIPHER"), Some(2));
    assert_eq!(mark_by_oid(algo.as_ref(), "1.2.3.4"), Some(2));
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
    assert!(is_listed(algo.as_ref(), "TEST-CIPHER"));

    denied.0.write().unwrap().push("TEST-CIPHER".to_string());
    assert!(!is_listed(algo.as_ref(), "TEST-CIPHER"));

    denied.0.write().unwrap().clear();
    assert!(is_listed(algo.as_ref(), "TEST-CIPHER"));
}
