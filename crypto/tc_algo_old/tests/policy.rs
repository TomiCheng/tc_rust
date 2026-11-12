use tc_algo_old::Policy;

#[test]
fn a_new_policy_has_both_sets_empty() {
    let policy = Policy::new();
    assert!(policy.allow().is_empty());
    assert!(policy.deny().is_empty());
}

#[test]
fn a_policy_takes_its_names_from_literals_or_from_strings_read_elsewhere() {
    let from_configuration = vec![String::from("MD5"), String::from("SHA-1")];
    let policy = Policy::new()
        .with_allow(["SHA-256", "AES/GCM/NOPADDING"])
        .with_deny(from_configuration);

    assert_eq!(policy.allow().len(), 2);
    assert!(policy.allow().contains("SHA-256"));
    assert_eq!(policy.deny().len(), 2);
    assert!(policy.deny().contains("MD5"));
}

#[test]
fn setting_a_set_again_replaces_it() {
    let policy = Policy::new().with_allow(["MD5"]).with_allow(["SHA-256"]);
    assert_eq!(policy.allow().len(), 1);
    assert!(policy.allow().contains("SHA-256"));
}
