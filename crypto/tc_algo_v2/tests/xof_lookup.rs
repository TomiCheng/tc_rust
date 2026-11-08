use std::any::Any;

use tc_algo_v2::digest::Digest;
use tc_algo_v2::xof::{Xof, XofEntry};
use tc_algo_v2::{
    Algo, AlgoBuilder, AlgoError, DefaultAlgoBuilder, DefaultAlgoContext, EntryBase, ErrorKind,
    ListPolicy, Params,
};
use tc_asn1::Asn1Oid;

struct NoParams;

impl Params for NoParams {
    fn as_any(&self) -> &dyn Any {
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

impl XofEntry for Row {
    fn create(&self) -> Box<dyn Xof> {
        Box::new(Marked(self.mark))
    }
}

// Its output repeats the mark of the row that created it, to tell which row a lookup found. An init
// adds INITIALIZED to the mark, to tell that a helper called it
struct Marked(u8);

const INITIALIZED: u8 = 100;

impl Digest for Marked {
    fn digest_size(&self) -> usize {
        1
    }

    fn byte_length(&self) -> usize {
        1
    }

    fn update(&mut self, _input: &[u8]) {}

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        Ok(self.output_final(output))
    }

    fn reset(&mut self) {}
}

impl Xof for Marked {
    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        self.0 += INITIALIZED;
        Ok(())
    }

    fn output(&mut self, output: &mut [u8]) -> usize {
        output.fill(self.0);
        output.len()
    }

    fn output_final(&mut self, output: &mut [u8]) -> usize {
        self.output(output)
    }
}

fn row(name: &'static str, aliases: &[&str], oids: &[&str], mark: u8) -> Box<dyn XofEntry> {
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

type Rows = fn(&DefaultAlgoContext) -> Vec<Box<dyn XofEntry>>;

fn older(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    vec![row("TEST-XOF", &["TESTX"], &["1.2.3.4"], 1)]
}

fn newer(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    vec![row("TEST-XOF", &[], &["1.2.3.4"], 2)]
}

fn builder_with(rows: &[Rows]) -> DefaultAlgoBuilder {
    let mut builder = DefaultAlgoBuilder::default();
    for row in rows {
        builder.reg_xof(*row);
    }
    builder
}

fn mark_of(mut xof: Box<dyn Xof>) -> u8 {
    xof.finalize_len(1)[0]
}

fn mark_by_name(algo: &dyn Algo, name: &str) -> Option<u8> {
    Some(mark_of(algo.xof().get_by_name(name).ok()?))
}

#[test]
fn an_xof_is_found_by_its_name_or_alias_whatever_their_case() {
    let algo = builder_with(&[older]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-XOF"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "test-xof"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "TestX"), Some(1));
}

#[test]
fn an_xof_is_found_by_its_oid() {
    let algo = builder_with(&[older]).build();
    let xof = algo.xof().get_by_oid(&oid("1.2.3.4")).unwrap();
    assert_eq!(mark_of(xof), 1);
}

#[test]
fn an_unknown_name_or_oid_is_reported_as_unknown_xof() {
    let algo = builder_with(&[older]).build();
    assert_eq!(
        algo.xof().get_by_name("NO-SUCH").err().unwrap().kind(),
        ErrorKind::UnknownXof
    );
    assert_eq!(
        algo.xof().get_by_oid(&oid("1.2.3.5")).err().unwrap().kind(),
        ErrorKind::UnknownXof
    );
}

#[test]
fn the_last_registered_xof_is_the_one_found_by_a_shared_name() {
    let algo = builder_with(&[older, newer]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-XOF"), Some(2));
}

#[test]
fn the_helpers_give_the_length_asked_for() {
    let algo = builder_with(&[older]).build();
    let xofs = algo.xof();

    let by_name = xofs.calculate_by_name("TEST-XOF", b"", 3);
    assert_eq!(by_name.unwrap(), [1; 3]);

    let by_oid = xofs.calculate_by_oid(&oid("1.2.3.4"), b"", 3);
    assert_eq!(by_oid.unwrap(), [1; 3]);
}

#[test]
fn the_helpers_with_params_init_the_xof_first() {
    let algo = builder_with(&[older]).build();
    let xofs = algo.xof();
    let initialized = 1 + INITIALIZED;

    let by_name = xofs.calculate_by_name_with("TEST-XOF", &NoParams, b"", 3);
    assert_eq!(by_name.unwrap(), [initialized; 3]);

    let by_oid = xofs.calculate_by_oid_with(&oid("1.2.3.4"), &NoParams, b"", 3);
    assert_eq!(by_oid.unwrap(), [initialized; 3]);
}

#[test]
fn the_helpers_report_an_unknown_xof() {
    let algo = builder_with(&[]).build();
    let xofs = algo.xof();
    let unknown = oid("1.2.3.5");

    let results = [
        xofs.calculate_by_name("NO-SUCH", b"", 1),
        xofs.calculate_by_oid(&unknown, b"", 1),
        xofs.calculate_by_name_with("NO-SUCH", &NoParams, b"", 1),
        xofs.calculate_by_oid_with(&unknown, &NoParams, b"", 1),
    ];
    for result in results {
        assert_eq!(result.unwrap_err().kind(), ErrorKind::UnknownXof);
    }
}

#[test]
fn a_policy_leaves_an_xof_out_of_the_list_but_a_lookup_still_finds_it() {
    let mut builder = builder_with(&[older]);
    builder.set_policy(ListPolicy::new().with_deny(["TEST-XOF"]));
    let algo = builder.build();

    let mut names = algo.xof().algorithms().map(|entry| entry.name());
    assert!(!names.any(|name| name == "TEST-XOF"));

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-XOF"), Some(1));
}
