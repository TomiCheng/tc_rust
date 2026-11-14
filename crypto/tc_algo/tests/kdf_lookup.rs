use tc_algo::kdf::{Kdf, KdfEntry};
use tc_algo::{
    Algo, AlgoBuilder, AlgoError, DefaultAlgoBuilder, DefaultAlgoContext, EntryBase, ErrorKind,
    ListPolicy, Params,
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

impl KdfEntry for Row {
    fn create(&self) -> Box<dyn Kdf> {
        Box::new(Marked(self.mark))
    }
}

// Its output repeats the mark of the row that created it, to tell which row a lookup found
struct Marked(u8);

impl tc_kdf::Kdf for Marked {
    type Error = AlgoError;

    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        output.fill(self.0);
        Ok(output.len())
    }
}

impl tc_kdf::KdfInit<dyn Params> for Marked {
    type Error = AlgoError;

    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        Ok(())
    }
}

impl Kdf for Marked {}

fn row(name: &'static str, aliases: &[&str], oids: &[&str], mark: u8) -> Box<dyn KdfEntry> {
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

type Rows = fn(&DefaultAlgoContext) -> Vec<Box<dyn KdfEntry>>;

fn older(_context: &DefaultAlgoContext) -> Vec<Box<dyn KdfEntry>> {
    vec![row("TEST-KDF", &["TESTK"], &["1.2.3.4"], 1)]
}

fn newer(_context: &DefaultAlgoContext) -> Vec<Box<dyn KdfEntry>> {
    vec![row("TEST-KDF", &[], &["1.2.3.4"], 2)]
}

fn builder_with(rows: &[Rows]) -> DefaultAlgoBuilder {
    let mut builder = DefaultAlgoBuilder::default();
    for row in rows {
        builder.reg_kdf(*row);
    }
    builder
}

fn mark_of(mut kdf: Box<dyn Kdf>) -> u8 {
    let mut output = [0; 1];
    kdf.generate_bytes(&mut output).unwrap();
    output[0]
}

fn mark_by_name(algo: &dyn Algo, name: &str) -> Option<u8> {
    Some(mark_of(algo.kdf().get_by_name(name).ok()?))
}

#[test]
fn a_kdf_is_found_by_its_name_or_alias_whatever_their_case() {
    let algo = builder_with(&[older]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-KDF"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "test-kdf"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "TestK"), Some(1));
}

#[test]
fn a_kdf_is_found_by_its_oid() {
    let algo = builder_with(&[older]).build();
    let kdf = algo.kdf().get_by_oid(&oid("1.2.3.4")).unwrap();
    assert_eq!(mark_of(kdf), 1);
}

#[test]
fn an_unknown_name_or_oid_is_reported_as_unknown_kdf() {
    let algo = builder_with(&[older]).build();
    assert_eq!(
        algo.kdf().get_by_name("NO-SUCH").err().unwrap().kind(),
        ErrorKind::UnknownKdf
    );
    assert_eq!(
        algo.kdf().get_by_oid(&oid("1.2.3.5")).err().unwrap().kind(),
        ErrorKind::UnknownKdf
    );
}

#[test]
fn the_last_registered_kdf_is_the_one_found_by_a_shared_name() {
    let algo = builder_with(&[older, newer]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-KDF"), Some(2));
}

#[test]
fn a_policy_leaves_a_kdf_out_of_the_list_but_a_lookup_still_finds_it() {
    let mut builder = builder_with(&[older]);
    builder.set_policy(ListPolicy::new().with_deny(["TEST-KDF"]));
    let algo = builder.build();

    let mut names = algo.kdf().algorithms().map(|entry| entry.name());
    assert!(!names.any(|name| name == "TEST-KDF"));

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-KDF"), Some(1));
}
