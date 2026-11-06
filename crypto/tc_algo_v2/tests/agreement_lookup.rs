use tc_algo_v2::agreement::{Agreement, AgreementEntry, SharedSecret};
use tc_algo_v2::params::KeyLength;
use tc_algo_v2::{
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

impl AgreementEntry for Row {
    fn create(&self) -> Box<dyn Agreement> {
        Box::new(Marked(self.mark))
    }
}

// Its secret is the mark of the row that created it, to tell which row a lookup found
struct Marked(u8);

impl Agreement for Marked {
    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        Ok(())
    }

    fn calculate_agreement(&self, _public_key: &dyn Params) -> Result<SharedSecret, AlgoError> {
        Ok(SharedSecret::new(vec![self.0]))
    }
}

fn row(name: &'static str, aliases: &[&str], oids: &[&str], mark: u8) -> Box<dyn AgreementEntry> {
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

type Rows = fn(&DefaultAlgoContext) -> Vec<Box<dyn AgreementEntry>>;

fn older(_context: &DefaultAlgoContext) -> Vec<Box<dyn AgreementEntry>> {
    vec![row("TEST-AGREEMENT", &["TESTA"], &["1.2.3.4"], 1)]
}

fn newer(_context: &DefaultAlgoContext) -> Vec<Box<dyn AgreementEntry>> {
    vec![row("TEST-AGREEMENT", &[], &["1.2.3.4"], 2)]
}

fn builder_with(rows: &[Rows]) -> DefaultAlgoBuilder {
    let mut builder = DefaultAlgoBuilder::default();
    for row in rows {
        builder.reg_agreement(*row);
    }
    builder
}

fn mark_of(agreement: Box<dyn Agreement>) -> u8 {
    let secret = agreement.calculate_agreement(&KeyLength::new(0)).unwrap();
    secret.as_bytes()[0]
}

fn mark_by_name(algo: &dyn Algo, name: &str) -> Option<u8> {
    Some(mark_of(algo.agreement().get_by_name(name).ok()?))
}

#[test]
fn an_agreement_is_found_by_its_name_or_alias_whatever_their_case() {
    let algo = builder_with(&[older]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-AGREEMENT"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "test-agreement"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "TestA"), Some(1));
}

#[test]
fn an_agreement_is_found_by_its_oid() {
    let algo = builder_with(&[older]).build();
    let agreement = algo.agreement().get_by_oid(&oid("1.2.3.4")).unwrap();
    assert_eq!(mark_of(agreement), 1);
}

#[test]
fn an_unknown_name_or_oid_is_reported_as_unknown_agreement() {
    let algo = builder_with(&[older]).build();
    assert_eq!(
        algo.agreement()
            .get_by_name("NO-SUCH")
            .err()
            .unwrap()
            .kind(),
        ErrorKind::UnknownAgreement
    );
    assert_eq!(
        algo.agreement()
            .get_by_oid(&oid("1.2.3.5"))
            .err()
            .unwrap()
            .kind(),
        ErrorKind::UnknownAgreement
    );
}

#[test]
fn the_last_registered_agreement_is_the_one_found_by_a_shared_name() {
    let algo = builder_with(&[older, newer]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-AGREEMENT"), Some(2));
}

#[test]
fn a_policy_leaves_an_agreement_out_of_the_list_but_a_lookup_still_finds_it() {
    let mut builder = builder_with(&[older]);
    builder.set_policy(ListPolicy::new().with_deny(["TEST-AGREEMENT"]));
    let algo = builder.build();

    let mut names = algo.agreement().algorithms().map(|entry| entry.name());
    assert!(!names.any(|name| name == "TEST-AGREEMENT"));

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-AGREEMENT"), Some(1));
}
