//! RFC 5126 §5.11.1 commitment types under `id-cti`, as Bouncy Castle's
//! `CommitmentTypeIdentifier` names them.

use tc_asn1::{Asn1Oid, NamedOid};

/// The commitments a `CommitmentTypeIndication` can name.
///
/// ```
/// use tc_asn1_esf::CommitmentTypeIdentifier;
///
/// assert_eq!(CommitmentTypeIdentifier::PROOF_OF_ORIGIN.dotted(), "1.2.840.113549.1.9.16.6.1");
/// assert_eq!(
///     CommitmentTypeIdentifier::from_oid(&CommitmentTypeIdentifier::PROOF_OF_ORIGIN.oid()),
///     Some(CommitmentTypeIdentifier::PROOF_OF_ORIGIN),
/// );
/// ```
pub struct CommitmentTypeIdentifier;

impl CommitmentTypeIdentifier {
    /// The signer created and approved the content.
    pub const PROOF_OF_ORIGIN: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x06, 0x01,
        ],
        "1.2.840.113549.1.9.16.6.1",
        "id-cti-ets-proofOfOrigin",
    );

    /// The signer received the content.
    pub const PROOF_OF_RECEIPT: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x06, 0x02,
        ],
        "1.2.840.113549.1.9.16.6.2",
        "id-cti-ets-proofOfReceipt",
    );

    /// A trusted provider delivered the content.
    pub const PROOF_OF_DELIVERY: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x06, 0x03,
        ],
        "1.2.840.113549.1.9.16.6.3",
        "id-cti-ets-proofOfDelivery",
    );

    /// The signer sent the content.
    pub const PROOF_OF_SENDER: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x06, 0x04,
        ],
        "1.2.840.113549.1.9.16.6.4",
        "id-cti-ets-proofOfSender",
    );

    /// The signer approved the content.
    pub const PROOF_OF_APPROVAL: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x06, 0x05,
        ],
        "1.2.840.113549.1.9.16.6.5",
        "id-cti-ets-proofOfApproval",
    );

    /// The signer created the content.
    pub const PROOF_OF_CREATION: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x06, 0x06,
        ],
        "1.2.840.113549.1.9.16.6.6",
        "id-cti-ets-proofOfCreation",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::PROOF_OF_ORIGIN,
        Self::PROOF_OF_RECEIPT,
        Self::PROOF_OF_DELIVERY,
        Self::PROOF_OF_SENDER,
        Self::PROOF_OF_APPROVAL,
        Self::PROOF_OF_CREATION,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
