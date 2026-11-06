use std::any::Any;

use tc_algo_v2::{
    Algo, AlgoBuilder, AlgoError, DefaultAlgoBuilder, DefaultAlgoContext, EntryBase, ErrorKind,
    ListPolicy, Params, WrapDirection, Wrapper, WrapperEntry,
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

impl WrapperEntry for Row {
    fn create(&self) -> Box<dyn Wrapper> {
        Box::new(Marked {
            mark: self.mark,
            direction: None,
        })
    }
}

// Its output is the mark of the row that created it, to tell which row a lookup found. It works
// only in the direction init gave it, to tell what a helper passed on
struct Marked {
    mark: u8,
    direction: Option<WrapDirection>,
}

impl Marked {
    fn output(&self, direction: WrapDirection) -> Result<Vec<u8>, AlgoError> {
        if self.direction == Some(direction) {
            Ok(vec![self.mark])
        } else {
            Err(AlgoError::new(ErrorKind::NotInitialized))
        }
    }
}

impl Wrapper for Marked {
    fn init(&mut self, direction: WrapDirection, _params: &dyn Params) -> Result<(), AlgoError> {
        self.direction = Some(direction);
        Ok(())
    }

    fn wrap(&mut self, _input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        self.output(WrapDirection::Wrap)
    }

    fn unwrap(&mut self, _input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        self.output(WrapDirection::Unwrap)
    }
}

fn row(name: &'static str, aliases: &[&str], oids: &[&str], mark: u8) -> Box<dyn WrapperEntry> {
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

type Rows = fn(&DefaultAlgoContext) -> Vec<Box<dyn WrapperEntry>>;

fn older(_context: &DefaultAlgoContext) -> Vec<Box<dyn WrapperEntry>> {
    vec![row("TEST-WRAP", &["TESTW"], &["1.2.3.4"], 1)]
}

fn newer(_context: &DefaultAlgoContext) -> Vec<Box<dyn WrapperEntry>> {
    vec![row("TEST-WRAP", &[], &["1.2.3.4"], 2)]
}

fn builder_with(rows: &[Rows]) -> DefaultAlgoBuilder {
    let mut builder = DefaultAlgoBuilder::default();
    for row in rows {
        builder.reg_wrap(*row);
    }
    builder
}

fn mark_of(mut wrapper: Box<dyn Wrapper>) -> u8 {
    wrapper.init(WrapDirection::Wrap, &NoParams).unwrap();
    wrapper.wrap(b"").unwrap()[0]
}

fn mark_by_name(algo: &dyn Algo, name: &str) -> Option<u8> {
    Some(mark_of(algo.wrap().get_by_name(name)?))
}

#[test]
fn a_wrapper_is_found_by_its_name_or_alias_whatever_their_case() {
    let algo = builder_with(&[older]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-WRAP"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "test-wrap"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "TestW"), Some(1));
}

#[test]
fn a_wrapper_is_found_by_its_oid() {
    let algo = builder_with(&[older]).build();
    let wrapper = algo.wrap().get_by_oid(&oid("1.2.3.4")).unwrap();
    assert_eq!(mark_of(wrapper), 1);
}

#[test]
fn an_unknown_name_or_oid_finds_nothing() {
    let algo = builder_with(&[older]).build();
    assert!(algo.wrap().get_by_name("NO-SUCH").is_none());
    assert!(algo.wrap().get_by_oid(&oid("1.2.3.5")).is_none());
}

#[test]
fn the_last_registered_wrapper_is_the_one_found_by_a_shared_name() {
    let algo = builder_with(&[older, newer]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-WRAP"), Some(2));
}

#[test]
fn the_helpers_init_the_wrapper_with_their_direction() {
    let algo = builder_with(&[older]).build();
    let wrappers = algo.wrap();
    let wrapper_oid = oid("1.2.3.4");

    let wrapped = wrappers.wrap_by_name("TEST-WRAP", &NoParams, b"");
    assert_eq!(wrapped.unwrap(), [1]);
    let wrapped = wrappers.wrap_by_oid(&wrapper_oid, &NoParams, b"");
    assert_eq!(wrapped.unwrap(), [1]);

    let unwrapped = wrappers.unwrap_by_name("TEST-WRAP", &NoParams, b"");
    assert_eq!(unwrapped.unwrap(), [1]);
    let unwrapped = wrappers.unwrap_by_oid(&wrapper_oid, &NoParams, b"");
    assert_eq!(unwrapped.unwrap(), [1]);
}

#[test]
fn the_helpers_report_an_unknown_wrapper() {
    let algo = builder_with(&[]).build();
    let wrappers = algo.wrap();
    let unknown = oid("1.2.3.5");

    let results = [
        wrappers.wrap_by_name("NO-SUCH", &NoParams, b""),
        wrappers.wrap_by_oid(&unknown, &NoParams, b""),
        wrappers.unwrap_by_name("NO-SUCH", &NoParams, b""),
        wrappers.unwrap_by_oid(&unknown, &NoParams, b""),
    ];
    for result in results {
        assert_eq!(result.unwrap_err().kind(), ErrorKind::UnknownWrapper);
    }
}

#[test]
fn a_policy_leaves_a_wrapper_out_of_the_list_but_a_lookup_still_finds_it() {
    let mut builder = builder_with(&[older]);
    builder.set_policy(ListPolicy::new().with_deny(["TEST-WRAP"]));
    let algo = builder.build();

    let mut names = algo.wrap().algorithms().map(|entry| entry.name());
    assert!(!names.any(|name| name == "TEST-WRAP"));

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-WRAP"), Some(1));
}
