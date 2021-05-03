use rustopals::block::{BlockCipher, BlockMode, PKCS7Error, AES128, CBC};

pub enum AdversaryError {
    PKCS7Error(PKCS7Error),
    ASCIIError(Vec<u8>),
}

pub struct Adversary {
    pub key: Vec<u8>,
}

impl Adversary {
    pub fn new() -> Adversary {
        use crate::gen_random_bytes;

        Adversary {
            key: gen_random_bytes(AES128::KEY_SIZE),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        CBC::new(&self.key).encrypt(&AES128, plaintext, &self.key)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<(), AdversaryError> {
        match CBC::new(&self.key).decrypt(&AES128, ciphertext, &self.key) {
            Ok(plaintext) => {
                if plaintext.iter().any(|&x| x > 127) {
                    Err(AdversaryError::ASCIIError(plaintext))
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(AdversaryError::PKCS7Error(e)),
        }
    }
}

mod test {
    use std::iter::repeat;

    use rustopals::block::{BlockCipher, AES128};
    use rustopals::util::iter::Xorable;

    #[test]
    fn test_crack() {
        const BLOCK_SIZE: usize = AES128::BLOCK_SIZE;

        let adversary = super::Adversary::new();

        loop {
            let plaintext = crate::gen_random_bytes(BLOCK_SIZE * 3);
            let ciphertext = adversary.encrypt(&plaintext);
            let c1 = &ciphertext[..BLOCK_SIZE];
            let modified_ciphertext = [c1, &[0; BLOCK_SIZE], c1].concat();

            let decrypted = adversary.decrypt(&modified_ciphertext);

            match decrypted {
                Err(super::AdversaryError::ASCIIError(plaintext)) => {
                    let padding_len = BLOCK_SIZE - (plaintext.len() % BLOCK_SIZE);

                    let p1 = &plaintext[..BLOCK_SIZE];
                    let p3 = [
                        &plaintext[BLOCK_SIZE * 2..],
                        &repeat(padding_len as u8)
                            .take(padding_len)
                            .collect::<Vec<_>>(),
                    ]
                    .concat();

                    let recovered_key = p1.xor(p3).collect::<Vec<_>>();

                    assert_eq!(recovered_key, adversary.key);
                    return;
                }
                _ => continue,
            }
        }
    }
}
