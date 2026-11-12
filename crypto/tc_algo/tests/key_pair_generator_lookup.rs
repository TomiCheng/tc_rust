use std::any::Any;

use tc_algo::generate::{KeyPair, KeyPairGenerator, KeyPairGeneratorEntry};
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

impl KeyPairGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyPairGenerator> {
        Box::new(Marked(self.mark))
    }
}

// Its keys hold the mark of the row that created it, to tell which row a lookup found
struct Marked(u8);

struct MarkedKey(u8);

impl Params for MarkedKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl KeyPairGenerator for Marked {
    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        Ok(())
    }

    fn generate(&mut self) -> Result<KeyPair, AlgoError> {
        Ok(KeyPair::new(
            Box::new(MarkedKey(self.0)),
            Box::new(MarkedKey(self.0)),
        ))
    }
}

fn row(
    name: &'static str,
    aliases: &[&str],
    oids: &[&str],
    mark: u8,
) -> Box<dyn KeyPairGeneratorEntry> {
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

type Rows = fn(&DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>>;

fn older(_context: &DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>> {
    vec![row("TEST-PAIR", &["TESTP"], &["1.2.3.4"], 1)]
}

fn newer(_context: &DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>> {
    vec![row("TEST-PAIR", &[], &["1.2.3.4"], 2)]
}

fn builder_with(rows: &[Rows]) -> DefaultAlgoBuilder {
    let mut builder = DefaultAlgoBuilder::default();
    for row in rows {
        builder.reg_key_pair_generator(*row);
    }
    builder
}

fn mark_of(pair: Result<KeyPair, AlgoError>) -> u8 {
    let pair = pair.unwrap();
    let key = pair.public().as_any().downcast_ref::<MarkedKey>();
    key.expect("a MarkedKey").0
}

fn mark_by_name(algo: &dyn Algo, name: &str) -> Option<u8> {
    let mut generator = algo.key_pair_generator().get_by_name(name).ok()?;
    Some(mark_of(generator.generate()))
}

#[test]
fn a_generator_is_found_by_its_name_or_alias_whatever_their_case() {
    let algo = builder_with(&[older]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-PAIR"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "test-pair"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "TestP"), Some(1));
}

#[test]
fn a_generator_is_found_by_its_oid() {
    let algo = builder_with(&[older]).build();
    let mut generator = algo
        .key_pair_generator()
        .get_by_oid(&oid("1.2.3.4"))
        .unwrap();
    assert_eq!(mark_of(generator.generate()), 1);
}

#[test]
fn the_last_registered_generator_is_the_one_found_by_a_shared_name() {
    let algo = builder_with(&[older, newer]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-PAIR"), Some(2));
}

#[test]
fn the_helpers_generate_a_pair_by_name_and_oid() {
    let algo = builder_with(&[older]).build();
    let generators = algo.key_pair_generator();
    assert_eq!(mark_of(generators.generate_by_name("TEST-PAIR")), 1);
    assert_eq!(mark_of(generators.generate_by_oid(&oid("1.2.3.4"))), 1);
}

#[test]
fn an_unknown_name_or_oid_is_reported_as_unknown_generator() {
    let algo = builder_with(&[older]).build();
    let generators = algo.key_pair_generator();
    let unknown = oid("1.2.3.5");
    let cases = [
        generators.generate_by_name("NO-SUCH"),
        generators.generate_by_oid(&unknown),
    ];
    for result in cases {
        let error = result.err().unwrap();
        assert_eq!(error.kind(), ErrorKind::UnknownGenerator);
    }
}

#[test]
fn a_policy_leaves_a_generator_out_of_the_list_but_a_lookup_still_finds_it() {
    let mut builder = builder_with(&[older]);
    builder.set_policy(ListPolicy::new().with_deny(["TEST-PAIR"]));
    let algo = builder.build();

    let mut names = algo
        .key_pair_generator()
        .algorithms()
        .map(|entry| entry.name());
    assert!(!names.any(|name| name == "TEST-PAIR"));

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-PAIR"), Some(1));
}
