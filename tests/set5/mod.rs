// Implement Diffie-Hellman - https://cryptopals.com/sets/5/challenges/33
#[test]
fn challenge33_implement_diffie_hellman() {
    use num_bigint::BigUint;
    use rustopals::key_exchange::DHOffer;

    let p = BigUint::from(37_usize);
    let g = BigUint::from(5_usize);

    let alice_offer = DHOffer::new_custom(p.clone(), &g);
    let bob_offer = DHOffer::new_custom(p, &g);

    let alice_session = alice_offer
        .clone()
        .establish(bob_offer.get_public())
        .unwrap();
    let bob_session = bob_offer.establish(alice_offer.get_public()).unwrap();

    assert_eq!(
        alice_session.get_shared_secret(),
        bob_session.get_shared_secret(),
    )
}

// Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection - https://cryptopals.com/sets/5/challenges/34
mod challenge34_dh_key_fixing;

// Implement DH with negotiated groups, and break with malicious "g" parameters - https://cryptopals.com/sets/5/challenges/35
mod challenge35_dh_negotiated_groups;

// Implement Secure Remote Password (SRP) - https://cryptopals.com/sets/5/challenges/36
// Break SRP with a zero key - https://cryptopals.com/sets/5/challenges/37
mod challenge36_37_srp;

// Offline dictionary attack on simplified SRP - https://cryptopals.com/sets/5/challenges/38
mod challenge38_offline_dictionary_srp;

// Implement RSA - https://cryptopals.com/sets/5/challenges/39
#[test]
fn challenge39_rsa() {
    use num_bigint::BigUint;
    use rustopals::rsa::{generate_rsa_keypair, E};

    let (public_key, private_key) = generate_rsa_keypair(1024, &E);

    let plaintext = BigUint::from(42_usize);
    let ciphertext = public_key.textbook_process(&plaintext).unwrap();

    assert_eq!(private_key.textbook_process(&ciphertext), Some(plaintext));
}
