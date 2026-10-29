use std::collections::HashSet;

use tc_asn1::NamedOid;
use tc_asn1_oid::{
    AnssiId, BsiId, CryptlibId, EacId, EdecId, GmId, GnuId, GsmaId, IanaId, IsaraId, KisaId,
    MicrosoftId, MiscId, NistId, NsriId, NttId, OiwId, SecId, TeletrustId,
};

type Lookup = fn(&tc_asn1::Asn1Oid) -> Option<NamedOid>;

fn tables() -> [(&'static str, &'static [NamedOid], Lookup); 19] {
    [
        ("anssi", AnssiId::ALL, AnssiId::from_oid),
        ("bsi", BsiId::ALL, BsiId::from_oid),
        ("cryptlib", CryptlibId::ALL, CryptlibId::from_oid),
        ("eac", EacId::ALL, EacId::from_oid),
        ("edec", EdecId::ALL, EdecId::from_oid),
        ("gm", GmId::ALL, GmId::from_oid),
        ("gnu", GnuId::ALL, GnuId::from_oid),
        ("gsma", GsmaId::ALL, GsmaId::from_oid),
        ("iana", IanaId::ALL, IanaId::from_oid),
        ("isara", IsaraId::ALL, IsaraId::from_oid),
        ("kisa", KisaId::ALL, KisaId::from_oid),
        ("microsoft", MicrosoftId::ALL, MicrosoftId::from_oid),
        ("misc", MiscId::ALL, MiscId::from_oid),
        ("nist", NistId::ALL, NistId::from_oid),
        ("nsri", NsriId::ALL, NsriId::from_oid),
        ("ntt", NttId::ALL, NttId::from_oid),
        ("oiw", OiwId::ALL, OiwId::from_oid),
        ("sec", SecId::ALL, SecId::from_oid),
        ("teletrust", TeletrustId::ALL, TeletrustId::from_oid),
    ]
}

#[test]
fn every_entry_encodes_its_dotted_form_and_is_found_by_its_identifier() {
    for (name, all, from_oid) in tables() {
        assert!(!all.is_empty(), "{name}");
        let mut seen = HashSet::new();
        for entry in all {
            assert_eq!(entry.oid().to_string(), entry.dotted(), "{name}");
            assert!(
                seen.insert(entry.dotted()),
                "{name} repeats {}",
                entry.dotted()
            );
            assert_eq!(from_oid(&entry.oid()), Some(*entry), "{name}");
        }
    }
}

#[test]
fn well_known_identifiers_have_their_registered_values() {
    for (entry, dotted) in [
        (NistId::ID_SHA256, "2.16.840.1.101.3.4.2.1"),
        (NistId::ID_AES256_GCM, "2.16.840.1.101.3.4.1.46"),
        (NistId::ID_ML_DSA_65, "2.16.840.1.101.3.4.3.18"),
        (NistId::ID_ALG_ML_KEM_768, "2.16.840.1.101.3.4.4.2"),
        (SecId::SEC_P256K1, "1.3.132.0.10"),
        (SecId::SEC_P384R1, "1.3.132.0.34"),
        (EdecId::ID_X25519, "1.3.101.110"),
        (EdecId::ID_ED448, "1.3.101.113"),
        (TeletrustId::BRAINPOOL_P256R1, "1.3.36.3.3.2.8.1.1.7"),
        (GmId::SM3, "1.2.156.10197.1.401"),
        (GmId::SM2P256V1, "1.2.156.10197.1.301"),
        (OiwId::ID_SHA1, "1.3.14.3.2.26"),
        (AnssiId::FRP256V1, "1.2.250.1.223.101.256.1"),
        (NttId::ID_CAMELLIA128_CBC, "1.2.392.200011.61.1.1.1.2"),
        (NsriId::ID_ARIA128_GCM, "1.2.410.200046.1.1.34"),
        (
            MicrosoftId::MICROSOFT_CERT_TEMPLATE_V2,
            "1.3.6.1.4.1.311.21.7",
        ),
        (MiscId::ID_BLAKE2B256, "1.3.6.1.4.1.1722.12.2.1.8"),
        (MiscId::ID_SCRYPT, "1.3.6.1.4.1.11591.4.11"),
        (MiscId::NETSCAPE_CERT_TYPE, "2.16.840.1.113730.1.1"),
    ] {
        assert_eq!(entry.dotted(), dotted);
    }
}

#[test]
fn a_repeated_identifier_resolves_to_its_first_name() {
    assert_eq!(NistId::ID_DSA_WITH_SHA2.dotted(), NistId::SIG_ALGS.dotted());
    assert_eq!(
        NistId::from_oid(&NistId::ID_DSA_WITH_SHA2.oid()),
        Some(NistId::SIG_ALGS)
    );
}
