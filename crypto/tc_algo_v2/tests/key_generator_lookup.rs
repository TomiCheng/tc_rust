use std::any::Any;

use tc_algo_v2::{
    Algo, AlgoBuilder, AlgoError, DefaultAlgoBuilder, DefaultAlgoContext, EntryBase, ErrorKind,
    KeyGenerator, KeyGeneratorEntry, ListPolicy, Params,
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

impl KeyGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyGenerator> {
        Box::new(Marked(self.mark))
    }
}

// Its key carries the mark of the row that created it, to tell which row a lookup found. An init
// adds INITIALIZED to the mark, to tell that a helper called it
struct Marked(u8);

const INITIALIZED: u8 = 100;

impl KeyGenerator for Marked {
    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        self.0 += INITIALIZED;
        Ok(())
    }

    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError> {
        Ok(Box::new(MarkedKey(self.0)))
    }
}

struct MarkedKey(u8);

impl Params for MarkedKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn row(
    name: &'static str,
    aliases: &[&str],
    oids: &[&str],
    mark: u8,
) -> Box<dyn KeyGeneratorEntry> {
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

type Rows = fn(&DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>>;

fn older(_context: &DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>> {
    vec![row("TEST-GENERATOR", &["TESTG"], &["1.2.3.4"], 1)]
}

fn newer(_context: &DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>> {
    vec![row("TEST-GENERATOR", &[], &["1.2.3.4"], 2)]
}

fn builder_with(rows: &[Rows]) -> DefaultAlgoBuilder {
    let mut builder = DefaultAlgoBuilder::default();
    for row in rows {
        builder.reg_key_generator(*row);
    }
    builder
}

fn mark_of(key: Result<Box<dyn Params>, AlgoError>) -> u8 {
    let key = key.unwrap();
    key.as_any().downcast_ref::<MarkedKey>().unwrap().0
}

fn mark_by_name(algo: &dyn Algo, name: &str) -> Option<u8> {
    Some(mark_of(algo.key_generator().get_by_name(name)?.generate()))
}

#[test]
fn a_generator_is_found_by_its_name_or_alias_whatever_their_case() {
    let algo = builder_with(&[older]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-GENERATOR"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "test-generator"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "TestG"), Some(1));
}

#[test]
fn a_generator_is_found_by_its_oid() {
    let algo = builder_with(&[older]).build();
    let generator = algo.key_generator().get_by_oid(&oid("1.2.3.4"));
    assert_eq!(mark_of(generator.unwrap().generate()), 1);
}

#[test]
fn an_unknown_name_or_oid_finds_nothing() {
    let algo = builder_with(&[older]).build();
    assert!(algo.key_generator().get_by_name("NO-SUCH").is_none());
    assert!(algo.key_generator().get_by_oid(&oid("1.2.3.5")).is_none());
}

#[test]
fn the_last_registered_generator_is_the_one_found_by_a_shared_name() {
    let algo = builder_with(&[older, newer]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-GENERATOR"), Some(2));
}

#[test]
fn the_helpers_generate_with_the_generator_a_lookup_finds() {
    let algo = builder_with(&[older]).build();
    let generators = algo.key_generator();
    assert_eq!(mark_of(generators.generate_by_name("TEST-GENERATOR")), 1);
    assert_eq!(mark_of(generators.generate_by_oid(&oid("1.2.3.4"))), 1);
}

#[test]
fn the_helpers_with_params_init_the_generator_first() {
    let algo = builder_with(&[older]).build();
    let generators = algo.key_generator();
    let params = MarkedKey(0);
    let cases = [
        generators.generate_by_name_with("TEST-GENERATOR", &params),
        generators.generate_by_oid_with(&oid("1.2.3.4"), &params),
    ];

    for key in cases {
        assert_eq!(mark_of(key), 1 + INITIALIZED);
    }
}

#[test]
fn the_helpers_report_an_unknown_generator() {
    let algo = builder_with(&[]).build();
    let generators = algo.key_generator();
    let params = MarkedKey(0);
    let unknown = oid("1.2.3.5");
    let cases = [
        generators.generate_by_name("NO-SUCH"),
        generators.generate_by_oid(&unknown),
        generators.generate_by_name_with("NO-SUCH", &params),
        generators.generate_by_oid_with(&unknown, &params),
    ];

    for result in cases {
        let error = result.err().unwrap();
        assert_eq!(error.kind(), ErrorKind::UnknownGenerator);
    }
}

#[test]
fn a_policy_leaves_a_generator_out_of_the_list_but_a_lookup_still_finds_it() {
    let mut builder = builder_with(&[older]);
    builder.set_policy(ListPolicy::new().with_deny(["TEST-GENERATOR"]));
    let algo = builder.build();

    let mut names = algo.key_generator().algorithms().map(|entry| entry.name());
    assert!(!names.any(|name| name == "TEST-GENERATOR"));

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-GENERATOR"), Some(1));
}
