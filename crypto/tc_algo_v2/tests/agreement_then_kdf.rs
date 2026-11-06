#![cfg(all(feature = "dh", feature = "hkdf-sha256"))]

use tc_algo_v2::params::HkdfParamsOwned;
use tc_algo_v2::params::dh_groups::rfc3526_2048;
use tc_algo_v2::{AlgoBuilder, DefaultAlgoBuilder};

#[test]
fn both_sides_of_an_agreement_derive_one_key_through_the_kdf() {
    let algo = DefaultAlgoBuilder::default().build();
    let group = rfc3526_2048();
    let generators = algo.key_pair_generator();
    let alice = generators.generate_by_name_with("DH", &group).unwrap();
    let bob = generators.generate_by_name_with("DH", &group).unwrap();

    let derive = |private, public| {
        let mut agreement = algo.agreement().get_by_name("DH").unwrap();
        agreement.init(private).unwrap();
        let secret = agreement.calculate_agreement(public).unwrap();

        let mut kdf = algo.kdf().get_by_name("HKDF-SHA256").unwrap();
        let params = HkdfParamsOwned::new(
            secret.as_bytes().to_vec(),
            vec![0xa5; 32],
            b"label".to_vec(),
        );
        kdf.init(&params).unwrap();
        let mut key = [0; 32];
        kdf.generate_bytes(&mut key).unwrap();
        key
    };

    assert_eq!(
        derive(alice.private(), bob.public()),
        derive(bob.private(), alice.public())
    );
}
