use tc_algo::kem::{
    Decapsulator, Encapsulator, KemDecapsulator, KemEncapsulator, KemEntry, KemInit,
};
use tc_algo::params::KeyLength;
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

impl KemEntry for Row {
    fn create_encapsulator(&self) -> Box<dyn Encapsulator> {
        Box::new(Marked(self.mark))
    }

    fn create_decapsulator(&self) -> Box<dyn Decapsulator> {
        Box::new(Marked(self.mark))
    }
}

// Its secret is the mark of the row that created it, to tell which row a lookup found
struct Marked(u8);

impl KemEncapsulator for Marked {
    type Error = AlgoError;

    fn encapsulation_length(&self) -> usize {
        1
    }

    fn secret_length(&self) -> usize {
        1
    }

    fn encapsulate(
        &mut self,
        encapsulation: &mut [u8],
        secret: &mut [u8],
    ) -> Result<(), AlgoError> {
        encapsulation[0] = self.0;
        secret[0] = self.0;
        Ok(())
    }
}

impl KemDecapsulator for Marked {
    type Error = AlgoError;

    fn encapsulation_length(&self) -> usize {
        1
    }

    fn secret_length(&self) -> usize {
        1
    }

    fn decapsulate(&mut self, encapsulation: &[u8], secret: &mut [u8]) -> Result<(), AlgoError> {
        secret[0] = encapsulation[0];
        Ok(())
    }
}

impl KemInit<dyn Params> for Marked {
    type Error = AlgoError;

    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        Ok(())
    }
}

impl Encapsulator for Marked {}

impl Decapsulator for Marked {}

fn row(name: &'static str, aliases: &[&str], oids: &[&str], mark: u8) -> Box<dyn KemEntry> {
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

type Rows = fn(&DefaultAlgoContext) -> Vec<Box<dyn KemEntry>>;

fn older(_context: &DefaultAlgoContext) -> Vec<Box<dyn KemEntry>> {
    vec![row("TEST-KEM", &["TESTK"], &["1.2.3.4"], 1)]
}

fn newer(_context: &DefaultAlgoContext) -> Vec<Box<dyn KemEntry>> {
    vec![row("TEST-KEM", &[], &["1.2.3.4"], 2)]
}

fn builder_with(rows: &[Rows]) -> DefaultAlgoBuilder {
    let mut builder = DefaultAlgoBuilder::default();
    for row in rows {
        builder.reg_kem(*row);
    }
    builder
}

fn mark_by_name(algo: &dyn Algo, name: &str) -> Option<u8> {
    let (_, secret) = algo
        .kem()
        .encapsulate_by_name(name, &KeyLength::new(0))
        .ok()?;
    Some(secret[0])
}

#[test]
fn a_kem_is_found_by_its_name_or_alias_whatever_their_case() {
    let algo = builder_with(&[older]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-KEM"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "test-kem"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "TestK"), Some(1));
}

#[test]
fn a_kem_is_found_by_its_oid() {
    let algo = builder_with(&[older]).build();
    let (_, secret) = algo
        .kem()
        .encapsulate_by_oid(&oid("1.2.3.4"), &KeyLength::new(0))
        .unwrap();
    assert_eq!(secret[0], 1);
}

#[test]
fn an_unknown_name_or_oid_is_reported_as_unknown_kem() {
    let algo = builder_with(&[older]).build();
    assert_eq!(
        algo.kem()
            .get_encapsulator_by_name("NO-SUCH")
            .err()
            .unwrap()
            .kind(),
        ErrorKind::UnknownKem
    );
    assert_eq!(
        algo.kem()
            .get_decapsulator_by_oid(&oid("1.2.3.5"))
            .err()
            .unwrap()
            .kind(),
        ErrorKind::UnknownKem
    );
}

#[test]
fn the_last_registered_kem_is_the_one_found_by_a_shared_name() {
    let algo = builder_with(&[older, newer]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-KEM"), Some(2));
}

#[test]
fn a_policy_leaves_a_kem_out_of_the_list_but_a_lookup_still_finds_it() {
    let mut builder = builder_with(&[older]);
    builder.set_policy(ListPolicy::new().with_deny(["TEST-KEM"]));
    let algo = builder.build();

    let mut names = algo.kem().algorithms().map(|entry| entry.name());
    assert!(!names.any(|name| name == "TEST-KEM"));

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-KEM"), Some(1));
}
