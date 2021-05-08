mod adversary {
    use num_bigint::BigUint;
    use num_integer::Integer;
    use once_cell::sync::Lazy;
    use rustopals::rsa::RSAPublicKey;

    use crate::RSA_KEYPAIR_0;

    static PLAINTEXT: Lazy<BigUint> = Lazy::new(|| {
        let bytes = base64::decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==").unwrap();
        BigUint::from_bytes_be(&bytes)
    });

    pub fn get_public_key() -> &'static RSAPublicKey {
        &RSA_KEYPAIR_0.0
    }

    pub fn get_ciphertext() -> Option<BigUint> {
        let public_key = &RSA_KEYPAIR_0.0;
        public_key.textbook_process(&PLAINTEXT)
    }

    pub fn oracle(ciphertext: &BigUint) -> Option<bool> {
        let private_key = &RSA_KEYPAIR_0.1;
        let plaintext = private_key.textbook_process(ciphertext)?;

        Some(plaintext.is_even())
    }

    pub fn assert_solution(guessed_plaintext: &BigUint) {
        assert_eq!(guessed_plaintext, &PLAINTEXT as &BigUint)
    }
}

#[test]
fn crack() {
    use num_bigint::BigUint;

    use self::adversary::{assert_solution, get_ciphertext, get_public_key, oracle};

    let public_key = get_public_key();

    let one = BigUint::from(1_usize);
    let two = BigUint::from(2_usize);
    let double = two.modpow(&public_key.e, &public_key.n);

    let mut ciphertext = get_ciphertext().unwrap();
    let mut low_bound = BigUint::from(0_usize);
    let mut high_bound = public_key.n.clone();

    while (&high_bound - &low_bound) > one {
        // `cargo test challenge46 -- --nocapture` to enjoy Hollywood-like cracking
        println!("{}", high_bound);

        ciphertext = (&ciphertext * &double) % &public_key.n;
        let half_bound = (&high_bound - &low_bound) / &two;

        let is_even = oracle(&ciphertext).unwrap();

        if is_even {
            high_bound -= half_bound;
        } else {
            low_bound += half_bound;
        }
    }

    assert_solution(&high_bound);
}
