use rustopals::block::{aes128, Cipher, PKCS7Error};

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
            key: gen_random_bytes(aes128::Cipher::KEY_SIZE),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        aes128::Cipher.encrypt_cbc_pkcs7(plaintext, &self.key, &self.key)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<(), AdversaryError> {
        match aes128::Cipher.decrypt_cbc_pkcs7(ciphertext, &self.key, &self.key) {
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
    use rustopals::block::{aes128, Cipher};
    use rustopals::util::iter::Xorable;
    use std::iter::repeat;

    #[test]
    fn test_crack() {
        let adversary = super::Adversary::new();

        const BLOCK_SIZE: usize = aes128::Cipher::BLOCK_SIZE;

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
