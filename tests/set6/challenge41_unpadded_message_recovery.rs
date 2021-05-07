use num_bigint::{BigUint, RandBigInt};
use num_traits::{Num, Zero};
use rand::thread_rng;
use rustopals::rsa::unpadded_message_recovery;

use crate::RSA_KEYPAIR_0;

mod adversary {
    use std::collections::HashSet;

    use num_bigint::BigUint;

    use crate::RSA_KEYPAIR_0;

    pub struct Server {
        cache: HashSet<BigUint>,
    }

    impl Server {
        pub fn new() -> Server {
            Server {
                cache: HashSet::new(),
            }
        }

        pub fn decrypt(&mut self, ciphertext: &BigUint) -> Option<BigUint> {
            if self.cache.contains(ciphertext) {
                return None;
            }

            self.cache.insert(ciphertext.clone());

            let private_key = &RSA_KEYPAIR_0.1;
            let plaintext = private_key.textbook_process(ciphertext).unwrap();

            Some(plaintext)
        }

        pub fn encrypt(plaintext: &BigUint) -> BigUint {
            let public_key = &RSA_KEYPAIR_0.0;

            public_key.textbook_process(plaintext).unwrap()
        }
    }
}

#[test]
fn normal_operation() {
    let plaintext = thread_rng().gen_biguint_range(
        &BigUint::zero(),
        &BigUint::from_str_radix("123456789123456789", 10).unwrap(),
    );

    let mut server = adversary::Server::new();

    let ciphertext = adversary::Server::encrypt(&plaintext);

    assert_eq!(server.decrypt(&ciphertext), Some(plaintext));
    assert_eq!(server.decrypt(&ciphertext), None);
}

#[test]
fn crack() {
    let plaintext = thread_rng().gen_biguint_range(
        &BigUint::zero(),
        &BigUint::from_str_radix("123456789123456789", 10).unwrap(),
    );

    let mut server = adversary::Server::new();

    let ciphertext = adversary::Server::encrypt(&plaintext);

    assert_eq!(&server.decrypt(&ciphertext).unwrap(), &plaintext);

    let public_key = &RSA_KEYPAIR_0.0;

    let s = BigUint::from(2_usize);

    assert_eq!(
        unpadded_message_recovery(public_key, &s, &ciphertext, |malleated| server
            .decrypt(malleated)
            .unwrap()),
        plaintext
    );
}
