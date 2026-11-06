use std::any::Any;

use tc_algo_v2::mac::{Mac, MacEntry};
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

impl MacEntry for Row {
    fn create(&self) -> Box<dyn Mac> {
        Box::new(Marked {
            mark: self.mark,
            initialized: false,
        })
    }
}

// Its tag is the mark of the row that created it, to tell which row a lookup found. It needs an
// init first, to tell that a helper called it
struct Marked {
    mark: u8,
    initialized: bool,
}

impl Mac for Marked {
    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        self.initialized = true;
        Ok(())
    }

    fn mac_size(&self) -> usize {
        1
    }

    fn update(&mut self, _input: &[u8]) -> Result<(), AlgoError> {
        Ok(())
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        if self.initialized {
            output[0] = self.mark;
            Ok(1)
        } else {
            Err(AlgoError::new(ErrorKind::NotInitialized))
        }
    }

    fn reset(&mut self) {}
}

fn row(name: &'static str, aliases: &[&str], oids: &[&str], mark: u8) -> Box<dyn MacEntry> {
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

type Rows = fn(&DefaultAlgoContext) -> Vec<Box<dyn MacEntry>>;

fn older(_context: &DefaultAlgoContext) -> Vec<Box<dyn MacEntry>> {
    vec![row("TEST-MAC", &["TESTM"], &["1.2.3.4"], 1)]
}

fn newer(_context: &DefaultAlgoContext) -> Vec<Box<dyn MacEntry>> {
    vec![row("TEST-MAC", &[], &["1.2.3.4"], 2)]
}

fn builder_with(rows: &[Rows]) -> DefaultAlgoBuilder {
    let mut builder = DefaultAlgoBuilder::default();
    for row in rows {
        builder.reg_mac(*row);
    }
    builder
}

fn mark_of(mut mac: Box<dyn Mac>) -> u8 {
    mac.init(&NoParams).unwrap();
    mac.finalize().unwrap()[0]
}

fn mark_by_name(algo: &dyn Algo, name: &str) -> Option<u8> {
    Some(mark_of(algo.mac().get_by_name(name).ok()?))
}

#[test]
fn a_mac_is_found_by_its_name_or_alias_whatever_their_case() {
    let algo = builder_with(&[older]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-MAC"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "test-mac"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "TestM"), Some(1));
}

#[test]
fn a_mac_is_found_by_its_oid() {
    let algo = builder_with(&[older]).build();
    let mac = algo.mac().get_by_oid(&oid("1.2.3.4")).unwrap();
    assert_eq!(mark_of(mac), 1);
}

#[test]
fn an_unknown_name_or_oid_is_reported_as_unknown_mac() {
    let algo = builder_with(&[older]).build();
    assert_eq!(
        algo.mac().get_by_name("NO-SUCH").err().unwrap().kind(),
        ErrorKind::UnknownMac
    );
    assert_eq!(
        algo.mac().get_by_oid(&oid("1.2.3.5")).err().unwrap().kind(),
        ErrorKind::UnknownMac
    );
}

#[test]
fn the_last_registered_mac_is_the_one_found_by_a_shared_name() {
    let algo = builder_with(&[older, newer]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-MAC"), Some(2));
}

#[test]
fn the_helpers_init_the_mac_and_calculate_with_it() {
    let algo = builder_with(&[older]).build();
    let macs = algo.mac();

    let by_name = macs.calculate_by_name("TEST-MAC", &NoParams, b"abc");
    assert_eq!(by_name.unwrap(), [1]);

    let by_oid = macs.calculate_by_oid(&oid("1.2.3.4"), &NoParams, b"abc");
    assert_eq!(by_oid.unwrap(), [1]);
}

#[test]
fn the_verify_helpers_tell_the_right_tag_from_a_wrong_one() {
    let algo = builder_with(&[older]).build();
    let macs = algo.mac();
    let mac_oid = oid("1.2.3.4");

    assert!(
        macs.verify_by_name("TEST-MAC", &NoParams, b"abc", &[1])
            .unwrap()
    );
    assert!(
        !macs
            .verify_by_name("TEST-MAC", &NoParams, b"abc", &[2])
            .unwrap()
    );

    assert!(
        macs.verify_by_oid(&mac_oid, &NoParams, b"abc", &[1])
            .unwrap()
    );
    assert!(
        !macs
            .verify_by_oid(&mac_oid, &NoParams, b"abc", &[2])
            .unwrap()
    );
}

#[test]
fn the_helpers_report_an_unknown_mac() {
    let algo = builder_with(&[]).build();
    let macs = algo.mac();
    let unknown = oid("1.2.3.5");

    let by_name = macs.calculate_by_name("NO-SUCH", &NoParams, b"");
    assert_eq!(by_name.unwrap_err().kind(), ErrorKind::UnknownMac);

    let by_oid = macs.calculate_by_oid(&unknown, &NoParams, b"");
    assert_eq!(by_oid.unwrap_err().kind(), ErrorKind::UnknownMac);

    let by_name = macs.verify_by_name("NO-SUCH", &NoParams, b"", &[]);
    assert_eq!(by_name.unwrap_err().kind(), ErrorKind::UnknownMac);

    let by_oid = macs.verify_by_oid(&unknown, &NoParams, b"", &[]);
    assert_eq!(by_oid.unwrap_err().kind(), ErrorKind::UnknownMac);
}

#[test]
fn a_policy_leaves_a_mac_out_of_the_list_but_a_lookup_still_finds_it() {
    let mut builder = builder_with(&[older]);
    builder.set_policy(ListPolicy::new().with_deny(["TEST-MAC"]));
    let algo = builder.build();

    let mut names = algo.mac().algorithms().map(|entry| entry.name());
    assert!(!names.any(|name| name == "TEST-MAC"));

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-MAC"), Some(1));
}
