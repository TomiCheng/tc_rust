use tc_algo_v2::{Algo, AlgoError, ErrorKind};
use tc_asn1::Asn1Oid;

struct NoAlgorithms;

impl Algo for NoAlgorithms {}

fn oid() -> Asn1Oid {
    "1.2.3.4".parse().unwrap()
}

fn kind_of<T>(result: Result<T, AlgoError>) -> ErrorKind {
    result.err().unwrap().kind()
}

#[test]
fn an_algo_without_providers_reports_every_name_as_unknown() {
    let algo = NoAlgorithms;
    let name = "NO-SUCH";
    assert_eq!(
        kind_of(algo.digest().get_by_name(name)),
        ErrorKind::UnknownDigest
    );
    assert_eq!(kind_of(algo.xof().get_by_name(name)), ErrorKind::UnknownXof);
    assert_eq!(kind_of(algo.mac().get_by_name(name)), ErrorKind::UnknownMac);
    assert_eq!(
        kind_of(algo.cipher().get_by_name(name)),
        ErrorKind::UnknownCipher
    );
    assert_eq!(
        kind_of(algo.wrap().get_by_name(name)),
        ErrorKind::UnknownWrapper
    );
    assert_eq!(
        kind_of(algo.key_generator().get_by_name(name)),
        ErrorKind::UnknownGenerator
    );
    assert_eq!(
        kind_of(algo.key_pair_generator().get_by_name(name)),
        ErrorKind::UnknownGenerator
    );
    assert_eq!(
        kind_of(algo.agreement().get_by_name(name)),
        ErrorKind::UnknownAgreement
    );
    assert_eq!(
        kind_of(algo.signer().get_by_name(name)),
        ErrorKind::UnknownSigner
    );
    assert_eq!(kind_of(algo.kdf().get_by_name(name)), ErrorKind::UnknownKdf);
    assert_eq!(kind_of(algo.pbe().get_by_name(name)), ErrorKind::UnknownPbe);
}

#[test]
fn an_algo_without_providers_reports_every_oid_as_unknown() {
    let algo = NoAlgorithms;
    let oid = oid();
    assert_eq!(
        kind_of(algo.digest().get_by_oid(&oid)),
        ErrorKind::UnknownDigest
    );
    assert_eq!(kind_of(algo.xof().get_by_oid(&oid)), ErrorKind::UnknownXof);
    assert_eq!(kind_of(algo.mac().get_by_oid(&oid)), ErrorKind::UnknownMac);
    assert_eq!(
        kind_of(algo.cipher().get_by_oid(&oid)),
        ErrorKind::UnknownCipher
    );
    assert_eq!(
        kind_of(algo.wrap().get_by_oid(&oid)),
        ErrorKind::UnknownWrapper
    );
    assert_eq!(
        kind_of(algo.key_generator().get_by_oid(&oid)),
        ErrorKind::UnknownGenerator
    );
    assert_eq!(
        kind_of(algo.key_pair_generator().get_by_oid(&oid)),
        ErrorKind::UnknownGenerator
    );
    assert_eq!(
        kind_of(algo.agreement().get_by_oid(&oid)),
        ErrorKind::UnknownAgreement
    );
    assert_eq!(
        kind_of(algo.signer().get_by_oid(&oid)),
        ErrorKind::UnknownSigner
    );
    assert_eq!(kind_of(algo.kdf().get_by_oid(&oid)), ErrorKind::UnknownKdf);
    assert_eq!(kind_of(algo.pbe().get_by_oid(&oid)), ErrorKind::UnknownPbe);
}
