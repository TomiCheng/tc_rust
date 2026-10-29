use tc_asn1::{
    Asn1Any, Asn1Constructed, Asn1Error, Asn1OctetString, Asn1SequenceOf, Decode, DecodingOptions,
    Encode, EncodingOptions, tag,
};
use tc_asn1_cms::content::ContentType;
use tc_asn1_pkcs::{
    AuthenticatedSafe, CertificationRequest, ContentInfo, EncryptedData, EncryptedPrivateKeyInfo,
    Pfx, Pkcs12Algorithm, SafeBag,
};

const REQ1: &[u8] = include_bytes!("data/pkcs10_req1.der");
const REQ2: &[u8] = include_bytes!("data/pkcs10_req2.der");
const PKCS12: &[u8] = include_bytes!("data/pkcs12.ber");

fn ber<T: Decode>(bytes: &[u8]) -> T {
    T::decode(bytes, &DecodingOptions::default()).unwrap().1
}

fn any<T: Encode>(value: &T) -> Asn1Any {
    ber(&value.encode_to_vec(&EncodingOptions::DER).unwrap())
}

/// Streaming encoders segment long OCTET STRINGs as `24 80`; this joins them.
fn octets(content: &ContentInfo) -> Vec<u8> {
    let raw = content.content().unwrap().raw();
    if raw[0] == 0x24 {
        let segments: Asn1Constructed<Asn1OctetString> = ber(raw);
        segments
            .items()
            .iter()
            .flat_map(|s| s.as_bytes().to_vec())
            .collect()
    } else {
        ber::<Asn1OctetString>(raw).as_bytes().to_vec()
    }
}

#[test]
fn bc_certification_request_round_trips_byte_for_byte_under_der() -> Result<(), Asn1Error> {
    let (len, request) = CertificationRequest::decode_der(REQ1, &DecodingOptions::default())?;
    assert_eq!(len, REQ1.len());
    assert_eq!(request.certification_request_info().version(), 0.into());
    assert_eq!(request.encode_to_vec(&EncodingOptions::DER)?, REQ1);
    Ok(())
}

/// BC `DerUniversalString` keeps raw octets; this UniversalString spends
/// 8 octets per character and is not UCS-4, so it is rejected.
#[test]
fn bc_universal_string_request_is_rejected_because_its_name_is_not_ucs4() {
    assert_eq!(
        CertificationRequest::decode(REQ2, &DecodingOptions::default()).unwrap_err(),
        Asn1Error::MalformedValue
    );
}

#[test]
fn bc_pkcs12_file_holds_a_shrouded_key_and_encrypted_certificates() {
    let pfx: Pfx = ber(PKCS12);
    assert_eq!(pfx.version(), 3.into());
    assert!(pfx.mac_data().is_some());
    assert_eq!(*pfx.auth_safe().content_type(), ContentType::DATA.oid());

    let safe: AuthenticatedSafe = ber(&octets(pfx.auth_safe()));
    let [keys, certs] = safe.content_infos() else {
        panic!("two content infos expected");
    };

    assert_eq!(*keys.content_type(), ContentType::DATA.oid());
    let bags: Asn1SequenceOf<SafeBag> = ber(&octets(keys));
    let bag = &bags.elements()[0];
    assert_eq!(*bag.bag_id(), Pkcs12Algorithm::PKCS8_SHROUDED_KEY_BAG.oid());
    let key: EncryptedPrivateKeyInfo = ber(bag.bag_value().raw());
    assert_eq!(
        *key.encryption_algorithm().algorithm(),
        Pkcs12Algorithm::PBE_WITH_SHA_AND_3_KEY_TRIPLE_DES_CBC.oid()
    );

    assert_eq!(*certs.content_type(), ContentType::ENCRYPTED_DATA.oid());
    let data: EncryptedData = ber(certs.content().unwrap().raw());
    assert!(data.encrypted_content_info().encrypted_content().is_some());
}

/// Takes the file apart and puts it back together as BC `Pkcs12Test.ImplTest` does.
fn rebuild(encoding: &[u8]) -> Vec<u8> {
    let pfx: Pfx = ber(encoding);
    let safe: AuthenticatedSafe = ber(&octets(pfx.auth_safe()));
    let [keys, certs] = safe.content_infos() else {
        panic!("two content infos expected");
    };

    let bags: Asn1SequenceOf<SafeBag> = ber(&octets(keys));
    let bag = &bags.elements()[0];
    let key: EncryptedPrivateKeyInfo = ber(bag.bag_value().raw());
    let key = EncryptedPrivateKeyInfo::new(
        key.encryption_algorithm().clone(),
        key.encrypted_data().clone(),
    );
    let mut rebuilt = SafeBag::new(bag.bag_id().clone(), any(&key));
    if let Some(attributes) = bag.bag_attributes() {
        rebuilt = rebuilt.with_bag_attributes(attributes.to_vec());
    }
    let bags = Asn1SequenceOf::new(vec![rebuilt]);
    let keys = data_info(&bags.encode_to_vec(&EncodingOptions::DER).unwrap());

    let data: EncryptedData = ber(certs.content().unwrap().raw());
    let certs = ContentInfo::new(ContentType::ENCRYPTED_DATA.oid()).with_content(any(&data));

    let safe = AuthenticatedSafe::new(vec![keys, certs]);
    let info = data_info(&safe.encode_to_vec(&EncodingOptions::DER).unwrap());
    let mut pfx_out = Pfx::new(info);
    if let Some(mac_data) = pfx.mac_data() {
        pfx_out = pfx_out.with_mac_data(mac_data.clone());
    }
    pfx_out.encode_to_vec(&EncodingOptions::DER).unwrap()
}

fn data_info(content: &[u8]) -> ContentInfo {
    ContentInfo::new(ContentType::DATA.oid())
        .with_content(Asn1Any::primitive(tag::OCTET_STRING, content))
}

#[test]
fn bc_pkcs12_file_rebuilt_from_its_parts_encodes_the_same_each_time() {
    let first = rebuild(PKCS12);
    let second = rebuild(&first);
    assert_eq!(first, second);
    assert_eq!(
        Pfx::decode_der(&first, &DecodingOptions::default())
            .unwrap()
            .0,
        first.len()
    );
}
