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
    use num_traits::Num;
    use rand::thread_rng;
    use rustopals::rsa::{e_3_broadcast_attack, generate_rsa_keypair_from_primes, E};

    let prime_0_p = BigUint::from_str_radix("1ae28a7709975a3584ccb3f6736a2e8cff920012d87195217dd4fe874978177217b294d6632fa4947f357141133aff91f20fa7d7d846cdf96a51348cc4a1f519", 16).unwrap();
    let prime_0_q = BigUint::from_str_radix("a8939a961989a83296bc351f0108118ca00ce185166ec5347a1729c55e9a000156409049a45f9a9e35fa4c5c26405021d0ff173c2c4fd6b0dabd6e706d5a7f5", 16).unwrap();
    let prime_1_p = BigUint::from_str_radix("efd9340b34a17a8a3d6a83ff9fa6c91b8f0be8f5353afc07e38e4c45eec9e13c80d57786d8b2737abf32f62c7bea51e853267df0f74846ba78a29c4f007e13f", 16).unwrap();
    let prime_1_q = BigUint::from_str_radix("5de5597c67e6763c87da21d4285e2344d4526da6572fdb2ecd9b347103788dfe5283f5259360220c6d915adbacf1cb052107c2022dae194b9f172143c2087fa7", 16).unwrap();
    let prime_2_p = BigUint::from_str_radix("e8e7ef9169a329cb5b11735b54368944862286584501694774065de9b48eaf9d3c616b698abcc1892cf2f220e78dbabd2a83eb4e740d768930eb9e2ea9477a81", 16).unwrap();
    let prime_2_q = BigUint::from_str_radix("661cda8aca9de55bdb30240d8e5516cc94b82cfa9bd205240f9b050dc6e4d9730724e8ffe8b6ccf9c1428646f0c21c1857503ab117d92b1c7445688a3db5e9af", 16).unwrap();

    let (public_key_0, private_key_0) =
        generate_rsa_keypair_from_primes(E.clone(), &prime_0_p, &prime_0_q).unwrap();
    let (public_key_1, private_key_1) =
        generate_rsa_keypair_from_primes(E.clone(), &prime_1_p, &prime_1_q).unwrap();
    let (public_key_2, private_key_2) =
        generate_rsa_keypair_from_primes(E.clone(), &prime_2_p, &prime_2_q).unwrap();

    let plaintext =
        thread_rng().gen_biguint_range(&BigUint::from(0_usize), &BigUint::from(100000000_usize));

    let c_0 = public_key_0.textbook_process(&plaintext).unwrap();
    let c_1 = public_key_1.textbook_process(&plaintext).unwrap();
    let c_2 = public_key_2.textbook_process(&plaintext).unwrap();

    assert_eq!(&private_key_0.textbook_process(&c_0).unwrap(), &plaintext);
    assert_eq!(&private_key_1.textbook_process(&c_1).unwrap(), &plaintext);
    assert_eq!(&private_key_2.textbook_process(&c_2).unwrap(), &plaintext);

    let decrypted_plaintext = e_3_broadcast_attack([
        (&public_key_0, &c_0),
        (&public_key_1, &c_1),
        (&public_key_2, &c_2),
    ]);

    assert_eq!(decrypted_plaintext, plaintext);
}
