use rustopals::rsa::{RSAPrivateKey, RSAPublicKey};

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

// Implement an E=3 RSA Broadcast attack - https://cryptopals.com/sets/5/challenges/40
#[test]
fn challenge40_e_3_rsa_broadcast_attack() {
    use num_bigint::{BigUint, RandBigInt};
    use rand::thread_rng;
    use rustopals::rsa::e_3_broadcast_attack;

    use crate::{RSA_KEYPAIR_0, RSA_KEYPAIR_1, RSA_KEYPAIR_2};

    let (public_key_0, private_key_0) = &RSA_KEYPAIR_0 as &(RSAPublicKey, RSAPrivateKey);
    let (public_key_1, private_key_1) = &RSA_KEYPAIR_1 as &(RSAPublicKey, RSAPrivateKey);
    let (public_key_2, private_key_2) = &RSA_KEYPAIR_2 as &(RSAPublicKey, RSAPrivateKey);

    let plaintext =
        thread_rng().gen_biguint_range(&BigUint::from(0_usize), &BigUint::from(100000000_usize));

    let c_0 = public_key_0.textbook_process(&plaintext).unwrap();
    let c_1 = public_key_1.textbook_process(&plaintext).unwrap();
    let c_2 = public_key_2.textbook_process(&plaintext).unwrap();

    assert_eq!(&private_key_0.textbook_process(&c_0).unwrap(), &plaintext);
    assert_eq!(&private_key_1.textbook_process(&c_1).unwrap(), &plaintext);
    assert_eq!(&private_key_2.textbook_process(&c_2).unwrap(), &plaintext);

    let decrypted_plaintext = e_3_broadcast_attack([
        (&RSA_KEYPAIR_0.0, &c_0),
        (&RSA_KEYPAIR_1.0, &c_1),
        (&RSA_KEYPAIR_2.0, &c_2),
    ]);

    assert_eq!(decrypted_plaintext, plaintext);
}
