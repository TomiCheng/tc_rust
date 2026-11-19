use std::sync::Arc;

use tc_pkcs::pkcs12::{Pkcs12Options, Pkcs12Store};
use tc_pkcs::{DefaultPkcsOperatorBuilder, PkcsError, PkcsOperator, PkcsOperatorBuilder};
use tc_x509::cert::X509Certificate;

const PASSWORD: &str = "secret";
const OPENSSL3: &[u8] = include_bytes!("data/p12_openssl3.p12");
const LEGACY: &[u8] = include_bytes!("data/p12_legacy.p12");
const PLAIN: &[u8] = include_bytes!("data/p12_plain.p12");

fn me() -> X509Certificate {
    X509Certificate::decode(include_bytes!("data/p12_me.der")).unwrap()
}

fn ca() -> X509Certificate {
    X509Certificate::decode(include_bytes!("data/p12_ca.der")).unwrap()
}

fn key_der(oper: &dyn PkcsOperator, store: &Pkcs12Store, alias: &str) -> PrivateKey {
    PrivateKey(
        oper.private_key_info()
            .encode(store.key(alias).unwrap())
            .unwrap(),
    )
}

#[derive(Debug, PartialEq)]
struct PrivateKey(tc_asn1_pkcs::PrivateKeyInfo);

#[test]
fn the_files_openssl_wrote_give_the_key_its_certificate_and_its_chain() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let files: [(&str, &[u8], Option<&str>); 3] = [
        ("PBES2 AES-256 and HMAC-SHA256", OPENSSL3, Some(PASSWORD)),
        ("3DES, RC2-40 and HMAC-SHA1", LEGACY, Some(PASSWORD)),
        ("no encryption and no MAC", PLAIN, None),
    ];
    for (name, file, password) in files {
        let store = oper
            .pkcs12()
            .load(file, password)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(store.aliases(), ["me"], "{name}");
        assert!(store.is_key_entry("ME"), "{name}");
        assert_eq!(store.certificate("me"), Some(&me()), "{name}");
        let chain = oper.pkcs12().certificate_chain(&store, "me").unwrap();
        assert_eq!(chain, [me(), ca()], "{name}");
    }
    let first = oper.pkcs12().load(OPENSSL3, Some(PASSWORD)).unwrap();
    let second = oper.pkcs12().load(LEGACY, Some(PASSWORD)).unwrap();
    assert_eq!(
        key_der(oper.as_ref(), &first, "me"),
        key_der(oper.as_ref(), &second, "me")
    );
}

#[test]
fn a_wrong_or_missing_password_is_refused() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let error = oper.pkcs12().load(OPENSSL3, Some("wrong")).unwrap_err();
    assert!(matches!(error, PkcsError::InvalidMac));
    let error = oper.pkcs12().load(OPENSSL3, None).unwrap_err();
    assert!(matches!(error, PkcsError::MissingPassword));
}

#[test]
fn a_store_saved_with_each_scheme_loads_back_the_same() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let store = oper.pkcs12().load(LEGACY, Some(PASSWORD)).unwrap();
    let pbes2 = Pkcs12Options::new()
        .with_key_algorithm_and_prf(
            "2.16.840.1.101.3.4.1.42".parse().unwrap(),
            "1.2.840.113549.2.9".parse().unwrap(),
        )
        .with_cert_algorithm_and_prf(
            "2.16.840.1.101.3.4.1.2".parse().unwrap(),
            "1.2.840.113549.2.9".parse().unwrap(),
        );
    let cases = [
        (
            "Bouncy Castle's defaults",
            Pkcs12Options::new(),
            Some(PASSWORD),
        ),
        ("PBES2", pbes2, Some(PASSWORD)),
        ("no password", Pkcs12Options::new(), None),
    ];
    for (name, options, password) in cases {
        let saved = oper
            .pkcs12()
            .save(&store, password, &options.with_iterations(1000))
            .unwrap();
        let back = oper
            .pkcs12()
            .load(&saved, password)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(back.aliases(), ["me"], "{name}");
        assert_eq!(
            key_der(oper.as_ref(), &back, "me"),
            key_der(oper.as_ref(), &store, "me"),
            "{name}"
        );
        let chain = oper.pkcs12().certificate_chain(&back, "me").unwrap();
        assert_eq!(chain, [me(), ca()], "{name}");
    }
}

#[test]
fn entries_are_set_replaced_and_deleted_by_alias() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let loaded = oper.pkcs12().load(PLAIN, None).unwrap();
    let key: Arc<dyn tc_algo::Params> = Arc::from(
        oper.private_key_info()
            .decode(
                &oper
                    .private_key_info()
                    .encode(loaded.key("me").unwrap())
                    .unwrap(),
            )
            .unwrap(),
    );

    let mut store = Pkcs12Store::new();
    let error = store
        .set_key_entry("me", key.clone(), Vec::new())
        .unwrap_err();
    assert!(matches!(error, PkcsError::NoCertificateChain));
    store.set_key_entry("me", key, vec![me(), ca()]).unwrap();
    store.set_certificate_entry("root", ca()).unwrap();
    let error = store.set_certificate_entry("Me", ca()).unwrap_err();
    assert!(matches!(error, PkcsError::AliasInUse));

    assert_eq!(store.aliases(), ["me", "root"]);
    assert!(store.is_certificate_entry("root"));
    assert_eq!(store.certificate_alias(&ca()), Some("root"));

    let saved = oper
        .pkcs12()
        .save(
            &store,
            Some(PASSWORD),
            &Pkcs12Options::new().with_iterations(1000),
        )
        .unwrap();
    let back = oper.pkcs12().load(&saved, Some(PASSWORD)).unwrap();
    assert_eq!(back.aliases(), ["me", "root"]);
    assert_eq!(back.certificate("root"), Some(&ca()));

    store.delete_entry("me");
    assert_eq!(store.aliases(), ["root"]);
}
