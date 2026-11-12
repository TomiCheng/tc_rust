use tc_algo::{EntryBase, ListPolicy, Policy};

struct Row {
    name: &'static str,
    aliases: Vec<String>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }
}

fn sha1() -> Row {
    Row {
        name: "SHA-1",
        aliases: vec!["SHA1".to_string()],
    }
}

fn sha256() -> Row {
    Row {
        name: "SHA-256",
        aliases: vec![],
    }
}

#[test]
fn an_empty_policy_lets_every_row_through() {
    let policy = ListPolicy::new();
    assert!(policy.filter(&sha1()));
    assert!(policy.filter(&sha256()));
}

#[test]
fn a_row_named_in_the_deny_list_is_left_out() {
    let policy = ListPolicy::new().with_deny(["SHA-1"]);
    assert!(!policy.filter(&sha1()));
    assert!(policy.filter(&sha256()));
}

#[test]
fn an_allow_list_leaves_out_every_row_it_does_not_name() {
    let policy = ListPolicy::new().with_allow(["SHA-256"]);
    assert!(!policy.filter(&sha1()));
    assert!(policy.filter(&sha256()));
}

#[test]
fn a_row_in_both_lists_is_left_out() {
    let policy = ListPolicy::new()
        .with_allow(["SHA-1", "SHA-256"])
        .with_deny(["SHA-1"]);
    assert!(!policy.filter(&sha1()));
    assert!(policy.filter(&sha256()));
}

#[test]
fn a_rule_finds_its_row_by_an_alias_and_without_regard_to_case() {
    for rule in ["SHA1", "sha1", "sha-1"] {
        let policy = ListPolicy::new().with_deny([rule]);
        assert!(!policy.filter(&sha1()), "{rule}");
    }
}

#[test]
fn an_allow_list_of_names_that_match_nothing_leaves_out_every_row() {
    let policy = ListPolicy::new().with_allow(["NO-SUCH-DIGEST"]);
    assert!(!policy.filter(&sha1()));
    assert!(!policy.filter(&sha256()));
}

#[test]
fn setting_a_list_again_replaces_it() {
    let policy = ListPolicy::new()
        .with_deny(["SHA-1"])
        .with_deny(["SHA-256"]);
    assert_eq!(policy.deny().len(), 1);
    assert!(policy.deny().contains("SHA-256"));
}

#[test]
fn names_can_come_from_strings_read_elsewhere() {
    let from_configuration = vec![String::from("SHA-1")];
    let policy = ListPolicy::new().with_deny(from_configuration);
    assert!(!policy.filter(&sha1()));
}
