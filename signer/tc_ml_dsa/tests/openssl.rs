//! ML-DSA：OpenSSL 3.5 產生的對照向量。同一個 seed 的公鑰、私鑰編碼與確定性簽章都要逐位元組
//! 相同，簽章要能驗過；三組參數各三組，涵蓋空的、短的與 255 bytes 的情境字串。

use tc_digest::Digest;
use tc_ml_dsa::{MlDsaParameters, MlDsaPrivateKey, MlDsaPublicKey, MlDsaSigner};
use tc_sha::Sha256Digest;
use tc_signer::{Signer, SignerInit};

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

fn params(set: &str) -> MlDsaParameters {
    match set {
        "44" => MlDsaParameters::ML_DSA_44,
        "65" => MlDsaParameters::ML_DSA_65,
        _ => MlDsaParameters::ML_DSA_87,
    }
}

#[test]
fn keys_and_deterministic_signatures_match_openssl() {
    let data = include_str!("data/openssl.txt");
    let mut count = 0;
    for line in data.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split(' ').collect();
        let params = params(fields[0]);
        let seed: [u8; 32] = bytes(fields[1]).try_into().unwrap();
        let (context, message) = (bytes(fields[2]), bytes(fields[3]));

        let private_key = MlDsaPrivateKey::from_seed(params, seed);
        let public_key = private_key.public_key();
        assert_eq!(
            sha256(&public_key.encoding()),
            bytes(fields[4]),
            "pk {line}"
        );
        assert_eq!(
            sha256(&private_key.encoding()),
            bytes(fields[5]),
            "sk {line}"
        );

        let mut signer = MlDsaSigner::deterministic(params);
        signer.set_context(&context).unwrap();
        signer.init(&private_key).unwrap();
        signer.update(&message).unwrap();
        let mut signature = vec![0; signer.max_signature_size()];
        assert_eq!(
            signer.generate_signature(&mut signature),
            Ok(signature.len())
        );
        assert_eq!(sha256(&signature), bytes(fields[6]), "sig {line}");

        let mut verifier = MlDsaSigner::deterministic(params);
        verifier.set_context(&context).unwrap();
        verifier.init(&public_key).unwrap();
        verifier.update(&message).unwrap();
        assert_eq!(verifier.verify_signature(&signature), Ok(true));

        // The same key through its encodings
        let decoded = MlDsaPrivateKey::from_encoding(params, &private_key.encoding()).unwrap();
        assert_eq!(decoded.public_key(), public_key);
        assert_eq!(
            MlDsaPublicKey::from_encoding(params, &public_key.encoding()).unwrap(),
            public_key
        );
        count += 1;
    }
    assert_eq!(count, 9);
}
