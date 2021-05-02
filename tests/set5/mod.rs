// Implement Diffie-Hellman - https://cryptopals.com/sets/5/challenges/33
#[test]
fn challenge33_implement_diffie_hellman() {
    use num_bigint::BigUint;
    use rustopals::key_exchange::DHOffer;

    let p = BigUint::from(37usize);
    let g = BigUint::from(5usize);

    let alice_offer = DHOffer::new_custom(p.clone(), &g);
    let bob_offer = DHOffer::new_custom(p.clone(), &g);

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