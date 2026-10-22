use tc_asn1::NamedOid;
use tc_security::{agreement, cipher, digest, generate, mac, params, signer, wrap};

fn oids(oids: &[NamedOid]) -> String {
    oids.iter()
        .map(NamedOid::name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn main() {
    println!("# cipher");
    for entry in cipher::algorithms() {
        println!("{entry}");
    }

    println!("\n# generate");
    for entry in generate::algorithms() {
        println!("{:<14} {}", entry.name(), oids(entry.oids()));
    }

    println!("\n# params");
    for entry in params::algorithms() {
        println!("{entry}");
    }

    println!("\n# mac");
    for entry in mac::algorithms() {
        println!("{entry}");
    }

    println!("\n# wrap");
    for entry in wrap::algorithms() {
        println!("{entry}");
    }

    println!("\n# agreement");
    for entry in agreement::algorithms() {
        println!("{entry}");
    }

    println!("\n# signer");
    for entry in signer::algorithms() {
        println!("{entry}");
    }

    println!("\n# digest");
    for entry in digest::algorithms() {
        println!("{entry}");
    }
}
