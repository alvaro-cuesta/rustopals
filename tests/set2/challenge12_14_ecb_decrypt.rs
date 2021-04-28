use ::std::iter;

static UNKNOWN_STRING: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

mod adversary {
    use rustopals::block::{aes128, Cipher};

    pub trait Encryptor {
        fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
    }

    pub struct EasyOracle {
        key: Vec<u8>,
    }

    impl EasyOracle {
        pub fn new() -> EasyOracle {
            EasyOracle {
                key: crate::gen_random_bytes(aes128::Cipher::BLOCK_SIZE),
            }
        }
    }

    impl Encryptor for EasyOracle {
        fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let decoded_base64 = ::base64::decode(super::UNKNOWN_STRING).unwrap();

            let extended_plaintext = plaintext
                .iter()
                .cloned()
                .chain(decoded_base64)
                .collect::<Vec<_>>();

            aes128::CIPHER.encrypt_ecb_pkcs7(&extended_plaintext, &self.key)
        }
    }

    pub struct HardOracle {
        key: Vec<u8>,
        pub prepend: Vec<u8>,
    }

    impl HardOracle {
        pub fn new(min: usize, max: usize) -> HardOracle {
            HardOracle {
                key: crate::gen_random_bytes(aes128::Cipher::KEY_SIZE),
                prepend: crate::gen_random_bytes_between(min, max),
            }
        }
    }

    impl Encryptor for HardOracle {
        fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let decoded_base64 = ::base64::decode(super::UNKNOWN_STRING).unwrap();

            let extended_plaintext = self
                .prepend
                .iter()
                .cloned()
                .chain(plaintext.iter().cloned())
                .chain(decoded_base64)
                .collect::<Vec<_>>();

            aes128::CIPHER.encrypt_ecb_pkcs7(&extended_plaintext, &self.key)
        }
    }
}

fn discover_block_size(oracle: impl Fn(&[u8]) -> Vec<u8>) -> usize {
    let mut last_encrypted = vec![];

    let mut to_encrypt = vec![];

    loop {
        let encrypted = oracle(&to_encrypt);
        let len_diff = encrypted.len() - last_encrypted.len();

        if len_diff > 1 && last_encrypted.len() > 0 {
            return len_diff;
        }

        last_encrypted = encrypted;
        to_encrypt.push(0u8);
    }
}

fn discover_is_ecb(oracle: impl Fn(&[u8]) -> Vec<u8>, block_size: usize) -> bool {
    let to_encrypt = iter::repeat(0u8).take(block_size * 2).collect::<Vec<_>>();

    let encrypted = oracle(&to_encrypt);

    let first_block = &encrypted[0..block_size];
    let second_block = &encrypted[block_size..block_size * 2];

    first_block == second_block
}

fn crack_ecb(oracle: impl Fn(&[u8]) -> Vec<u8>, block_size: usize) -> u8 {
    use std::collections::HashMap;

    let to_encrypt_for_last_byte = iter::repeat(0u8).take(block_size - 1).collect::<Vec<_>>();

    let dict = (0u8..=255)
        .map(|b| {
            let encrypted = to_encrypt_for_last_byte
                .iter()
                .cloned()
                .chain(iter::once(b))
                .collect::<Vec<_>>();

            (encrypted, b)
        })
        .collect::<HashMap<_, _>>();

    dict[&oracle(&to_encrypt_for_last_byte)]
}

mod test {
    use super::adversary::Encryptor;
    use rustopals::block::{aes128, Cipher};

    static TEST_MIN_PREPEND: usize = 10;
    static TEST_MAX_PREPEND: usize = 32;

    #[test]
    fn test_discover_block_size_easy() {
        let easy_oracle = super::adversary::EasyOracle::new();
        let easy_fn = |plaintext: &[u8]| easy_oracle.encrypt(plaintext);

        assert_eq!(
            super::discover_block_size(easy_fn),
            aes128::Cipher::BLOCK_SIZE,
        );
    }

    #[test]
    fn test_discover_ecb_easy() {
        let easy_oracle = super::adversary::EasyOracle::new();
        let easy_fn = |plaintext: &[u8]| easy_oracle.encrypt(plaintext);

        assert!(super::discover_is_ecb(easy_fn, aes128::Cipher::BLOCK_SIZE));
    }
}
