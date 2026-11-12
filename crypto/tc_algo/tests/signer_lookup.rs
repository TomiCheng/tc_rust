use tc_algo::params::KeyLength;
use tc_algo::signer::{Signer, SignerEntry};
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

impl SignerEntry for Row {
    fn create(&self) -> Box<dyn Signer> {
        Box::new(Marked {
            mark: self.mark,
            initialized: false,
        })
    }
}

// Its signature is the mark of the row that created it, to tell which row a lookup found
struct Marked {
    mark: u8,
    initialized: bool,
}

impl Signer for Marked {
    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        self.initialized = true;
        Ok(())
    }

    fn max_signature_size(&self) -> usize {
        4
    }

    fn update(&mut self, _input: &[u8]) -> Result<(), AlgoError> {
        Ok(())
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        if !self.initialized {
            return Err(AlgoError::new(ErrorKind::NotInitialized));
        }
        output[0] = self.mark;
        Ok(1)
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, AlgoError> {
        if !self.initialized {
            return Err(AlgoError::new(ErrorKind::NotInitialized));
        }
        Ok(signature == [self.mark])
    }

    fn reset(&mut self) {}
}

fn row(name: &'static str, aliases: &[&str], oids: &[&str], mark: u8) -> Box<dyn SignerEntry> {
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

type Rows = fn(&DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>>;

fn older(_context: &DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>> {
    vec![row("TEST-SIGNER", &["TESTS"], &["1.2.3.4"], 1)]
}

fn newer(_context: &DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>> {
    vec![row("TEST-SIGNER", &[], &["1.2.3.4"], 2)]
}

fn builder_with(rows: &[Rows]) -> DefaultAlgoBuilder {
    let mut builder = DefaultAlgoBuilder::default();
    for row in rows {
        builder.reg_signer(*row);
    }
    builder
}

fn mark_of(mut signer: Box<dyn Signer>) -> u8 {
    signer.init(&KeyLength::new(0)).unwrap();
    signer.sign().unwrap()[0]
}

fn mark_by_name(algo: &dyn Algo, name: &str) -> Option<u8> {
    Some(mark_of(algo.signer().get_by_name(name).ok()?))
}

#[test]
fn a_signer_is_found_by_its_name_or_alias_whatever_their_case() {
    let algo = builder_with(&[older]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-SIGNER"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "test-signer"), Some(1));
    assert_eq!(mark_by_name(algo.as_ref(), "TestS"), Some(1));
}

#[test]
fn a_signer_is_found_by_its_oid() {
    let algo = builder_with(&[older]).build();
    let signer = algo.signer().get_by_oid(&oid("1.2.3.4")).unwrap();
    assert_eq!(mark_of(signer), 1);
}

#[test]
fn an_unknown_name_or_oid_is_reported_as_unknown_signer() {
    let algo = builder_with(&[older]).build();
    assert_eq!(
        algo.signer().get_by_name("NO-SUCH").err().unwrap().kind(),
        ErrorKind::UnknownSigner
    );
    assert_eq!(
        algo.signer()
            .get_by_oid(&oid("1.2.3.5"))
            .err()
            .unwrap()
            .kind(),
        ErrorKind::UnknownSigner
    );
}

#[test]
fn the_last_registered_signer_is_the_one_found_by_a_shared_name() {
    let algo = builder_with(&[older, newer]).build();
    assert_eq!(mark_by_name(algo.as_ref(), "TEST-SIGNER"), Some(2));
}

#[test]
fn sign_gives_as_many_bytes_as_generate_signature_wrote() {
    let algo = builder_with(&[older]).build();
    let mut signer = algo.signer().get_by_name("TEST-SIGNER").unwrap();
    signer.init(&KeyLength::new(0)).unwrap();
    assert_eq!(signer.sign().unwrap(), [1]);
}

#[test]
fn a_policy_leaves_a_signer_out_of_the_list_but_a_lookup_still_finds_it() {
    let mut builder = builder_with(&[older]);
    builder.set_policy(ListPolicy::new().with_deny(["TEST-SIGNER"]));
    let algo = builder.build();

    let mut names = algo.signer().algorithms().map(|entry| entry.name());
    assert!(!names.any(|name| name == "TEST-SIGNER"));

    assert_eq!(mark_by_name(algo.as_ref(), "TEST-SIGNER"), Some(1));
}
