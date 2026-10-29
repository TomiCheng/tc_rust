use tc_asn1::{Asn1Error, Asn1Utf8String, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_cmp::{PkiFailureInfo, PkiFreeText, PkiStatus, PkiStatusInfo};

#[test]
fn failure_info_flags_sit_at_their_named_bit_positions() {
    let flags = [
        PkiFailureInfo::BAD_ALG,
        PkiFailureInfo::BAD_MESSAGE_CHECK,
        PkiFailureInfo::BAD_REQUEST,
        PkiFailureInfo::BAD_TIME,
        PkiFailureInfo::BAD_CERT_ID,
        PkiFailureInfo::BAD_DATA_FORMAT,
        PkiFailureInfo::WRONG_AUTHORITY,
        PkiFailureInfo::INCORRECT_DATA,
        PkiFailureInfo::MISSING_TIME_STAMP,
        PkiFailureInfo::BAD_POP,
        PkiFailureInfo::CERT_REVOKED,
        PkiFailureInfo::CERT_CONFIRMED,
        PkiFailureInfo::WRONG_INTEGRITY,
        PkiFailureInfo::BAD_RECIPIENT_NONCE,
        PkiFailureInfo::TIME_NOT_AVAILABLE,
        PkiFailureInfo::UNACCEPTED_POLICY,
        PkiFailureInfo::UNACCEPTED_EXTENSION,
        PkiFailureInfo::ADD_INFO_NOT_AVAILABLE,
        PkiFailureInfo::BAD_SENDER_NONCE,
        PkiFailureInfo::BAD_CERT_TEMPLATE,
        PkiFailureInfo::SIGNER_NOT_TRUSTED,
        PkiFailureInfo::TRANSACTION_ID_IN_USE,
        PkiFailureInfo::UNSUPPORTED_VERSION,
        PkiFailureInfo::NOT_AUTHORIZED,
        PkiFailureInfo::SYSTEM_UNAVAIL,
        PkiFailureInfo::SYSTEM_FAILURE,
        PkiFailureInfo::DUPLICATE_CERT_REQ,
    ];
    for (index, flag) in flags.into_iter().enumerate() {
        let der = flag.encode_to_vec(&EncodingOptions::DER).unwrap();
        let octet = index / 8;
        assert_eq!(der[1] as usize, 2 + octet);
        assert_eq!(der[2] as usize, 7 - index % 8);
        assert_eq!(der[3 + octet], 0x80 >> (index % 8));
        assert_eq!(
            PkiFailureInfo::decode_der(&der, &DecodingOptions::default())
                .unwrap()
                .1,
            flag
        );
    }
}

#[test]
fn bc_bad_data_format_failure_info_matches_its_flags() {
    let info = PkiFailureInfo::BAD_REQUEST
        | PkiFailureInfo::BAD_TIME
        | PkiFailureInfo::BAD_DATA_FORMAT
        | PkiFailureInfo::INCORRECT_DATA;
    assert_eq!(
        info.encode_to_vec(&EncodingOptions::DER).unwrap(),
        [3, 2, 0, 0x35]
    );
}

#[test]
fn undefined_failure_bits_and_trailing_zero_bits_under_der_are_rejected() {
    let options = DecodingOptions::default();
    assert_eq!(
        PkiFailureInfo::decode_der(&[3, 5, 4, 0, 0, 0, 0x10], &options),
        Err(Asn1Error::MalformedValue)
    );
    assert_eq!(
        PkiFailureInfo::decode_der(&[3, 2, 0, 0x80], &options),
        Err(Asn1Error::NotDer)
    );
    assert_eq!(
        PkiFailureInfo::decode(&[3, 2, 0, 0x80], &options)
            .unwrap()
            .1,
        PkiFailureInfo::BAD_ALG
    );
}

#[test]
fn statuses_outside_0_to_6_are_rejected() {
    assert_eq!(
        PkiStatus::decode_der(&[2, 1, 7], &DecodingOptions::default()),
        Err(Asn1Error::MalformedValue)
    );
    assert_eq!(
        PkiStatus::decode_der(&[2, 1, 6], &DecodingOptions::default())
            .unwrap()
            .1,
        PkiStatus::KeyUpdateWarning
    );
}

#[test]
fn free_text_needs_at_least_one_string() {
    assert_eq!(PkiFreeText::new(vec![]), Err(Asn1Error::MalformedValue));
    assert_eq!(
        PkiFreeText::decode_der(&[0x30, 0], &DecodingOptions::default()),
        Err(Asn1Error::MalformedValue)
    );
}

#[test]
fn status_info_round_trips_with_text_and_failure_info() {
    let info = PkiStatusInfo::new(PkiStatus::Rejection)
        .with_status_string(PkiFreeText::new(vec![Asn1Utf8String::new("no")]).unwrap())
        .with_fail_info(PkiFailureInfo::BAD_POP);
    let der = info.encode_to_vec(&EncodingOptions::DER).unwrap();
    assert_eq!(
        PkiStatusInfo::decode_der(&der, &DecodingOptions::default())
            .unwrap()
            .1,
        info
    );
}
