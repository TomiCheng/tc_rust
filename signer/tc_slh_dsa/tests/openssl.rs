//! SLH-DSA：OpenSSL 3.5 產生的對照向量。同樣的種子算出的公鑰與確定性簽章都要逐位元組相同，簽章
//! 要能驗過；十二組參數各一組，f 參數組再多一組不帶情境字串的。

use tc_digest::Digest;
use tc_sha::Sha256Digest;
use tc_signer::{Signer, SignerInit};
use tc_slh_dsa::{SlhDsaParameters, SlhDsaPrivateKey, SlhDsaSigner};

fn bytes(hex: &str) -> Vec<u8> {
    if hex == "-" {
        return Vec::new();
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut digest = Sha256Digest::new();
    digest.update(data);
    let mut hash = vec![0; 32];
    digest.do_final(&mut hash);
    hash
}

fn params(name: &str) -> SlhDsaParameters {
    SlhDsaParameters::ALL
        .into_iter()
        .find(|params| params.name() == name)
        .unwrap()
}

fn check(small: bool) -> usize {
    let data = include_str!("data/openssl.txt");
    let mut count = 0;
    for line in data.lines().filter(|line| !line.starts_with('#')) {
        if line.split(' ').next().unwrap().ends_with('s') != small {
            continue;
        }
        let fields: Vec<&str> = line.split(' ').collect();
        let params = params(fields[0]);
        let n = params.n();
        let seeds = bytes(fields[1]);
        let (context, message) = (bytes(fields[2]), bytes(fields[3]));

        let private_key =
            SlhDsaPrivateKey::from_seeds(params, &seeds[..n], &seeds[n..2 * n], &seeds[2 * n..])
                .unwrap();
        let public_key = private_key.public_key();
        assert_eq!(
            sha256(&public_key.encoding()),
            bytes(fields[4]),
            "pk {}",
            fields[0]
        );

        let mut signer = SlhDsaSigner::deterministic(params);
        signer.set_context(&context).unwrap();
        signer.init(&private_key).unwrap();
        signer.update(&message).unwrap();
        let mut signature = vec![0; signer.max_signature_size()];
        assert_eq!(
            signer.generate_signature(&mut signature),
            Ok(signature.len())
        );
        assert_eq!(sha256(&signature), bytes(fields[5]), "sig {}", fields[0]);

        let mut verifier = SlhDsaSigner::deterministic(params);
        verifier.set_context(&context).unwrap();
        verifier.init(&public_key).unwrap();
        verifier.update(&message).unwrap();
        assert_eq!(
            verifier.verify_signature(&signature),
            Ok(true),
            "{}",
            fields[0]
        );
        count += 1;
    }
    count
}

#[test]
fn the_fast_sets_match_openssl() {
    assert_eq!(check(false), 12);
}

#[test]
#[ignore = "slow in a debug build; run with --release --ignored"]
fn the_small_sets_match_openssl() {
    assert_eq!(check(true), 6);
}
