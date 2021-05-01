mod adversary {
    use rustopals::block::{aes128, Cipher as BlockCipher};
    use rustopals::stream::{ctr, Cipher as StreamCipher};

    pub struct LoginSystem {
        key: Vec<u8>,
        nonce: Vec<u8>,
    }

    impl LoginSystem {
        pub fn new() -> LoginSystem {
            use crate::gen_random_bytes;

            LoginSystem {
                key: gen_random_bytes(aes128::Cipher::KEY_SIZE),
                nonce: gen_random_bytes(aes128::Cipher::BLOCK_SIZE),
            }
        }

        pub fn generate_payload(&self, userdata: &str) -> Vec<u8> {
            let sanitized = userdata.replace("=", "").replace(";", "");

            let plaintext = [
                "comment1=cooking%20MCs;userdata=",
                &sanitized,
                ";comment2=%20like%20a%20pound%20of%20bacon",
            ]
            .concat();

            ctr::Cipher::from_nonce(&aes128::Cipher, &self.key, &self.nonce)
                .process(plaintext.bytes())
                .collect()
        }

        pub fn is_admin(&self, payload: &[u8]) -> bool {
            use std::str;

            let plaintext = ctr::Cipher::from_nonce(&aes128::Cipher, &self.key, &self.nonce)
                .process(payload)
                .collect::<Vec<_>>();

            // Whoopsies! Rust is so cool I had to mark this as unsafe
            // Forced to use unsafe because String::from_utf8 detected wrong UTF-8 in the garbage block
            let credentials = unsafe { str::from_utf8_unchecked(&plaintext) };

            println!("{:?}", credentials);

            credentials.contains(";admin=true;")
        }
    }
}

fn crack(login: &adversary::LoginSystem) -> Vec<u8> {
    // 0123456789abcdef0123456789abcdef0123456789abcdef0123456
    // comment1=cooking%20MCs;userdata=0123456789a;comment2...
    //                                 ;admin=true
    //                                 !admin!true

    let mut payload = login.generate_payload("!admin!true");

    payload[0x20] ^= ';' as u8 ^ '!' as u8;
    payload[0x20 + 0x06] ^= '=' as u8 ^ '!' as u8;

    payload
}

mod test {
    #[test]
    fn test_crack() {
        let login = super::adversary::LoginSystem::new();

        assert!(login.is_admin(&super::crack(&login)))
    }
}