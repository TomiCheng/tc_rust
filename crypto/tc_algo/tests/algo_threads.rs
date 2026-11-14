use std::sync::Arc;
use std::thread;

use tc_algo::{Algo, AlgoBuilder, DefaultAlgoBuilder, ListPolicy};

#[test]
fn an_algo_with_a_policy_can_be_shared_between_threads() {
    let mut builder = DefaultAlgoBuilder::default();
    builder.set_policy(ListPolicy::new().with_deny(["NO-SUCH"]));
    let algo: Arc<dyn Algo> = builder.build().into();
    let expected = algo.digest().algorithms().count();

    let threads: Vec<_> = (0..4)
        .map(|_| {
            let algo = Arc::clone(&algo);
            thread::spawn(move || algo.digest().algorithms().count())
        })
        .collect();

    for thread in threads {
        assert_eq!(thread.join().unwrap(), expected);
    }
}

#[test]
fn a_provider_can_be_shared_between_threads() {
    let algo = DefaultAlgoBuilder::default().build();
    let digests = algo.digest();
    let expected = digests.algorithms().count();

    thread::scope(|scope| {
        let thread = scope.spawn(|| digests.algorithms().count());
        assert_eq!(thread.join().unwrap(), expected);
    });
}

#[cfg(feature = "sha256")]
#[test]
fn each_thread_gets_its_own_digest_from_a_shared_algo() {
    let algo: Arc<dyn Algo> = DefaultAlgoBuilder::default().build().into();
    let expected = algo.digest().calculate_by_name("SHA-256", b"abc").unwrap();

    let threads: Vec<_> = (0..4)
        .map(|_| {
            let algo = Arc::clone(&algo);
            thread::spawn(move || {
                let mut digest = algo.digest().get_by_name("SHA-256").unwrap();
                digest.try_update(b"abc").unwrap();
                digest.finalize().unwrap()
            })
        })
        .collect();

    for thread in threads {
        assert_eq!(thread.join().unwrap(), expected);
    }
}
