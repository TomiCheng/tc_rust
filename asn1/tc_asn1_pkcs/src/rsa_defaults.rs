//! Exact RFC 8017 defaults and allocation-free comparisons.

use alloc::vec;

use tc_asn1::{Asn1Null, Asn1Object, Asn1OctetString};
use tc_asn1_x509::AlgorithmIdentifier;

use crate::Pkcs1Algorithm;

pub(crate) fn sha1() -> AlgorithmIdentifier {
    AlgorithmIdentifier::with_null(Pkcs1Algorithm::SHA1.oid())
}

pub(crate) fn mgf1_sha1() -> AlgorithmIdentifier {
    AlgorithmIdentifier::with_parameters(
        Pkcs1Algorithm::MGF1.oid(),
        Asn1Object::sequence(vec![Pkcs1Algorithm::SHA1.oid().into(), Asn1Null.into()]),
    )
}

pub(crate) fn p_specified_empty() -> AlgorithmIdentifier {
    AlgorithmIdentifier::with_parameters(
        Pkcs1Algorithm::P_SPECIFIED.oid(),
        Asn1OctetString::new(&[]),
    )
}

pub(crate) fn is_sha1(value: &AlgorithmIdentifier) -> bool {
    *value.algorithm() == Pkcs1Algorithm::SHA1
        && matches!(value.parameters(), Some(Asn1Object::Null(_)))
}

pub(crate) fn is_mgf1_sha1(value: &AlgorithmIdentifier) -> bool {
    if *value.algorithm() != Pkcs1Algorithm::MGF1 {
        return false;
    }
    matches!(
        value.parameters(),
        Some(Asn1Object::SequenceOf(seq))
            if matches!(seq.elements(), [Asn1Object::Oid(oid), Asn1Object::Null(_)]
                if *oid == Pkcs1Algorithm::SHA1)
    )
}

pub(crate) fn is_p_specified_empty(value: &AlgorithmIdentifier) -> bool {
    *value.algorithm() == Pkcs1Algorithm::P_SPECIFIED
        && matches!(value.parameters(), Some(Asn1Object::OctetString(octets)) if octets.as_bytes().is_empty())
}
