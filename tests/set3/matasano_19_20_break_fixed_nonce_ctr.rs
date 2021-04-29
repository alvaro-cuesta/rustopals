mod adversary {
    use rustopals::block::aes128;
    use rustopals::block::Cipher as BlockCipher;
    use rustopals::stream::{ctr, Cipher};
    use rustopals::util;

    pub struct Encryptor {
        key: Vec<u8>,
    }

    impl Encryptor {
        pub fn new() -> Encryptor {
            Encryptor {
                key: util::generate_bytes(aes128::Cipher::BLOCK_SIZE),
            }
        }

        pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let nonce = vec![0; aes128::Cipher::BLOCK_SIZE / 2];

            ctr::Cipher::from_nonce(&aes128::Cipher, &self.key, &nonce)
                .process(plaintext)
                .collect()
        }
    }
}

/*
Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted against the same keystream. This is very bad.

Understanding that, like most stream ciphers (including RC4, and obviously any block cipher run in CTR mode), the actual "encryption" of a byte of data boils down to a single XOR operation, it should be plain that:

CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
And since the keystream is the same for every ciphertext:

CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
say!")
Attack this cryptosystem piecemeal: guess letters, use expected English language frequence to validate guesses, catch common English trigrams, and so on.

Don't overthink it.
Points for automating this, but part of the reason I'm having you do this is that I think this approach is suboptimal.
*/

#[test]
fn crack_substitutions_19() {
    static STRINGS: &'static str = include_str!("19.txt");

    let strings = STRINGS
        .lines()
        .map(|x| base64::decode(x).unwrap())
        .collect::<Vec<_>>();

    let encryptor = adversary::Encryptor::new();

    let encrypted_strings = strings
        .iter()
        .map(|x| encryptor.encrypt(x))
        .collect::<Vec<_>>();

    unimplemented!();
}

/*
Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would repeating-key XOR.

Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the same thing.

To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest ciphertext will work).

Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the ciphertext you XOR'd.
*/

#[test]
fn crack_statistically_20() {
    static STRINGS: &'static str = include_str!("20.txt");

    let strings = STRINGS
        .lines()
        .map(|x| base64::decode(x).unwrap())
        .collect::<Vec<_>>();

    let encryptor = adversary::Encryptor::new();

    let encrypted_strings = strings
        .iter()
        .map(|x| encryptor.encrypt(x))
        .collect::<Vec<_>>();

    unimplemented!();
}
