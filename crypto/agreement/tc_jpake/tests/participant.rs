//! `JPakeParticipant`：Bouncy Castle `JPakeParticipantTest` 的情境。J-PAKE 每次都取新的亂數，
//! 沒有固定的測試向量；改驗證雙方的結果一致，以及錯誤的酬載與步驟順序被拒絕。

use rand::rngs::ThreadRng;
use tc_bigint::PaddedBigUint;
use tc_jpake::standard_groups::sun_jce_1024;
use tc_jpake::{
    JPakeError, JPakeParams, JPakeParticipant, JPakeRound1Payload, JPakeRound2Payload,
    JPakeRound3Payload, JPakeState,
};

type Participant = JPakeParticipant<ThreadRng>;

fn participant(participant_id: &str, password: &[u8]) -> Participant {
    let mut participant = JPakeParticipant::new(rand::rng());
    participant
        .init(&JPakeParams::new(participant_id, password).with_group(sun_jce_1024()))
        .unwrap();
    participant
}

fn alice() -> Participant {
    participant("alice", b"password")
}

fn bob() -> Participant {
    participant("bob", b"password")
}

/// 跑完第一輪並建立雙方第二輪的酬載，回傳 Alice 與 Bob 的第二輪酬載。
fn run_until_round2_creation(
    alice: &mut Participant,
    bob: &mut Participant,
) -> (JPakeRound2Payload, JPakeRound2Payload) {
    let alice_round1 = alice.create_round1_payload_to_send().unwrap();
    let bob_round1 = bob.create_round1_payload_to_send().unwrap();
    alice.validate_round1_payload_received(&bob_round1).unwrap();
    bob.validate_round1_payload_received(&alice_round1).unwrap();
    (
        alice.create_round2_payload_to_send().unwrap(),
        bob.create_round2_payload_to_send().unwrap(),
    )
}

#[test]
fn a_participant_needs_init_and_a_password() {
    let mut participant = JPakeParticipant::new(rand::rng());
    assert_eq!(participant.state(), None);
    assert_eq!(
        participant.create_round1_payload_to_send(),
        Err(JPakeError::NotInitialized)
    );
    assert_eq!(
        participant.init(&JPakeParams::new("participantId", b"").with_group(sun_jce_1024())),
        Err(JPakeError::EmptyPassword)
    );
    assert_eq!(participant.state(), None);
    participant
        .init(&JPakeParams::new("participantId", b"password").with_group(sun_jce_1024()))
        .unwrap();
    assert_eq!(participant.state(), Some(JPakeState::Initialized));
}

#[test]
fn a_password_that_is_zero_modulo_q_is_refused_at_init() {
    let group = sun_jce_1024();
    let password = tc_bigint::ArrayEncoding::<u8>::to_be(&(group.q() * 3u32));
    let mut participant = JPakeParticipant::new(rand::rng());
    assert_eq!(
        participant.init(&JPakeParams::new("participantId", &password).with_group(group)),
        Err(JPakeError::InvalidPassword)
    );
}

#[test]
fn a_successful_exchange_gives_both_sides_the_same_keying_material() {
    let (mut alice, mut bob) = (alice(), bob());
    let (alice_round2, bob_round2) = run_until_round2_creation(&mut alice, &mut bob);
    alice.validate_round2_payload_received(&bob_round2).unwrap();
    bob.validate_round2_payload_received(&alice_round2).unwrap();

    let alice_key = alice.calculate_keying_material().unwrap();
    let bob_key = bob.calculate_keying_material().unwrap();
    let alice_round3 = alice.create_round3_payload_to_send(&alice_key).unwrap();
    let bob_round3 = bob.create_round3_payload_to_send(&bob_key).unwrap();
    alice
        .validate_round3_payload_received(&bob_round3, &alice_key)
        .unwrap();
    bob.validate_round3_payload_received(&alice_round3, &bob_key)
        .unwrap();
    assert_eq!(*alice_key, *bob_key);
    assert_eq!(alice.state(), Some(JPakeState::Round3Validated));
}

#[test]
fn a_wrong_password_fails_key_confirmation_on_both_sides() {
    let (mut alice, mut bob) = (alice(), participant("bob", b"wrong"));
    let (alice_round2, bob_round2) = run_until_round2_creation(&mut alice, &mut bob);
    alice.validate_round2_payload_received(&bob_round2).unwrap();
    bob.validate_round2_payload_received(&alice_round2).unwrap();

    let alice_key = alice.calculate_keying_material().unwrap();
    let bob_key = bob.calculate_keying_material().unwrap();
    assert_ne!(*alice_key, *bob_key);
    let alice_round3 = alice.create_round3_payload_to_send(&alice_key).unwrap();
    let bob_round3 = bob.create_round3_payload_to_send(&bob_key).unwrap();
    assert_eq!(
        alice.validate_round3_payload_received(&bob_round3, &alice_key),
        Err(JPakeError::MacTagMismatch)
    );
    assert_eq!(
        bob.validate_round3_payload_received(&alice_round3, &bob_key),
        Err(JPakeError::MacTagMismatch)
    );
}

#[test]
fn each_step_is_refused_when_repeated_or_taken_too_early() {
    let (mut alice, mut bob) = (alice(), bob());
    let one = PaddedBigUint::from(1u8);
    let premature = JPakeError::PrematureStep;
    let repeated = JPakeError::RepeatedStep;

    // 第一輪
    assert_eq!(alice.state(), Some(JPakeState::Initialized));
    assert_eq!(alice.create_round2_payload_to_send(), Err(premature));
    let alice_round1 = alice.create_round1_payload_to_send().unwrap();
    assert_eq!(alice.state(), Some(JPakeState::Round1Created));
    assert_eq!(alice.create_round1_payload_to_send(), Err(repeated));
    assert_eq!(alice.create_round2_payload_to_send(), Err(premature));
    let dummy_round2 = JPakeRound2Payload::new(
        "bob",
        one.clone(),
        alice_round1.knowledge_proof_for_x1().clone(),
    );
    assert_eq!(
        alice.validate_round2_payload_received(&dummy_round2),
        Err(premature)
    );
    let bob_round1 = bob.create_round1_payload_to_send().unwrap();
    alice.validate_round1_payload_received(&bob_round1).unwrap();
    assert_eq!(alice.state(), Some(JPakeState::Round1Validated));
    assert_eq!(
        alice.validate_round1_payload_received(&bob_round1),
        Err(repeated)
    );
    bob.validate_round1_payload_received(&alice_round1).unwrap();

    // 第二輪
    let alice_round2 = alice.create_round2_payload_to_send().unwrap();
    assert_eq!(alice.state(), Some(JPakeState::Round2Created));
    assert_eq!(alice.create_round2_payload_to_send(), Err(repeated));
    assert_eq!(
        alice.calculate_keying_material().map(|_| ()),
        Err(premature)
    );
    let dummy_round3 = JPakeRound3Payload::new("bob", vec![0; 32]);
    assert_eq!(
        alice.validate_round3_payload_received(&dummy_round3, &one),
        Err(premature)
    );
    let bob_round2 = bob.create_round2_payload_to_send().unwrap();
    alice.validate_round2_payload_received(&bob_round2).unwrap();
    assert_eq!(alice.state(), Some(JPakeState::Round2Validated));
    assert_eq!(
        alice.validate_round2_payload_received(&bob_round2),
        Err(repeated)
    );
    bob.validate_round2_payload_received(&alice_round2).unwrap();
    assert_eq!(alice.create_round3_payload_to_send(&one), Err(premature));

    // 協商結果
    let alice_key = alice.calculate_keying_material().unwrap();
    assert_eq!(alice.state(), Some(JPakeState::KeyCalculated));
    assert_eq!(alice.calculate_keying_material().map(|_| ()), Err(repeated));
    let bob_key = bob.calculate_keying_material().unwrap();

    // 第三輪
    let alice_round3 = alice.create_round3_payload_to_send(&alice_key).unwrap();
    assert_eq!(alice.state(), Some(JPakeState::Round3Created));
    assert_eq!(
        alice.create_round3_payload_to_send(&alice_key),
        Err(repeated)
    );
    let bob_round3 = bob.create_round3_payload_to_send(&bob_key).unwrap();
    alice
        .validate_round3_payload_received(&bob_round3, &alice_key)
        .unwrap();
    assert_eq!(alice.state(), Some(JPakeState::Round3Validated));
    assert_eq!(
        alice.validate_round3_payload_received(&bob_round3, &alice_key),
        Err(repeated)
    );
    bob.validate_round3_payload_received(&alice_round3, &bob_key)
        .unwrap();
}

#[test]
fn validating_round_1_first_leaves_round_2_refused_rather_than_panicking() {
    let mut alice = alice();
    let bob_round1 = bob().create_round1_payload_to_send().unwrap();
    alice.validate_round1_payload_received(&bob_round1).unwrap();
    assert_eq!(
        alice.create_round1_payload_to_send(),
        Err(JPakeError::RepeatedStep)
    );
    assert_eq!(
        alice.create_round2_payload_to_send(),
        Err(JPakeError::PrematureStep)
    );
}

#[test]
fn round_1_payloads_that_fail_validation_are_refused() {
    let bob_round1 = bob().create_round1_payload_to_send().unwrap();
    alice()
        .validate_round1_payload_received(&bob_round1)
        .unwrap();

    let mut alice = alice();
    let own = alice.create_round1_payload_to_send().unwrap();
    assert_eq!(
        alice.validate_round1_payload_received(&own),
        Err(JPakeError::SameParticipantId)
    );

    let with = |gx2: &PaddedBigUint, proof1, proof2| {
        JPakeRound1Payload::new(
            bob_round1.participant_id(),
            bob_round1.gx1().clone(),
            gx2.clone(),
            proof1,
            proof2,
        )
    };
    let proof1 = || bob_round1.knowledge_proof_for_x1().clone();
    let proof2 = || bob_round1.knowledge_proof_for_x2().clone();
    assert_eq!(
        self::alice().validate_round1_payload_received(&with(
            &PaddedBigUint::from(1u8),
            proof1(),
            proof2()
        )),
        Err(JPakeError::GxIsOne)
    );

    let other = bob().create_round1_payload_to_send().unwrap();
    assert_eq!(
        self::alice().validate_round1_payload_received(&with(
            bob_round1.gx2(),
            other.knowledge_proof_for_x1().clone(),
            proof2()
        )),
        Err(JPakeError::InvalidProof),
        "the proof for x3"
    );
    assert_eq!(
        self::alice().validate_round1_payload_received(&with(
            bob_round1.gx2(),
            proof1(),
            other.knowledge_proof_for_x2().clone()
        )),
        Err(JPakeError::InvalidProof),
        "the proof for x4"
    );
}

#[test]
fn round_2_payloads_that_fail_validation_are_refused() {
    let (mut alice1, mut bob1) = (alice(), bob());
    let (_, bob_round2) = run_until_round2_creation(&mut alice1, &mut bob1);
    alice1
        .validate_round2_payload_received(&bob_round2)
        .unwrap();

    let (mut alice2, mut bob2) = (alice(), bob());
    let (alice_round2, _) = run_until_round2_creation(&mut alice2, &mut bob2);
    assert_eq!(
        alice2.validate_round2_payload_received(&alice_round2),
        Err(JPakeError::SameParticipantId)
    );

    let (mut alice3, mut bob3) = (alice(), bob());
    run_until_round2_creation(&mut alice3, &mut bob3);
    let (mut alice4, mut bob4) = (alice(), bob());
    let (_, other_bob_round2) = run_until_round2_creation(&mut alice4, &mut bob4);
    assert_eq!(
        alice3.validate_round2_payload_received(&other_bob_round2),
        Err(JPakeError::InvalidProof),
        "a payload from another exchange"
    );

    let carol_round2 = JPakeRound2Payload::new(
        "carol",
        bob_round2.a().clone(),
        bob_round2.knowledge_proof_for_x2s().clone(),
    );
    assert_eq!(
        alice2.validate_round2_payload_received(&carol_round2),
        Err(JPakeError::UnexpectedParticipant)
    );
}
