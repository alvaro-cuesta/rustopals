/// Implement PKCS#7 padding - https://cryptopals.com/sets/2/challenges/9
#[test]
fn challenge9_pkcs7_padding() {
    use rustopals::block::pkcs7;

    const INPUT: &[u8] = b"YELLOW SUBMARINE";
    const BLOCK_SIZE: u8 = 20;
    const EXPECTED: &[u8] = b"YELLOW SUBMARINE\x04\x04\x04\x04";

    assert_eq!(pkcs7::pad(INPUT, BLOCK_SIZE), EXPECTED,);
}

/// Implement CBC mode - https://cryptopals.com/sets/2/challenges/10
mod challenge10_cbc_mode {
    use rustopals::block::{BlockMode, AES128, CBC};

    const CIPHERTEXT: &str = include_str!("10.txt");
    const PLAINTEXT: &[u8] = include_bytes!("10.solution.txt");
    const KEY: &[u8] = b"YELLOW SUBMARINE";
    const IV: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[test]
    fn encrypt() {
        let ciphertext_no_newlines = CIPHERTEXT.lines().collect::<String>();
        let expected_ciphertext = ::base64::decode(&ciphertext_no_newlines).unwrap();

        assert_eq!(
            CBC::new(IV).encrypt_impl(&AES128, PLAINTEXT, KEY,),
            expected_ciphertext,
        );
    }

    #[test]
    fn decrypt() {
        let ciphertext_no_newlines = CIPHERTEXT.lines().collect::<String>();
        let ciphertext = base64::decode(&ciphertext_no_newlines).unwrap();

        assert_eq!(
            CBC::new(IV).decrypt_impl(&AES128, &ciphertext, KEY),
            PLAINTEXT,
        );
    }
}

/// An ECB/CBC detection oracle - https://cryptopals.com/sets/2/challenges/11
mod challenge11_ecb_cbc_detection_oracle {
    use rustopals::block;
    use rustopals::block::{BlockCipher, BlockMode, AES128, CBC, ECB};

    /// An oracle as required by https://cryptopals.com/sets/2/ but snitching its chosen cipher mode
    fn snitch_oracle(plaintext: &[u8]) -> (block::Mode, Vec<u8>) {
        // Generate a random number of bytes to append and prepend
        let prepend = crate::gen_random_bytes_between(5, 11);
        let append = crate::gen_random_bytes_between(5, 11);

        // Extend plaintext and pad it
        let extended_plaintext = prepend
            .into_iter()
            .chain(plaintext.iter().cloned())
            .chain(append.into_iter())
            .collect::<Vec<_>>();

        // Generate random key
        let key = crate::gen_random_bytes(AES128::KEY_SIZE);

        // Choose randomly between ECB and CBC
        if rand::random::<bool>() {
            (
                block::Mode::ECB,
                ECB.encrypt(&AES128, &extended_plaintext, &key),
            )
        } else {
            let iv = crate::gen_random_bytes(AES128::BLOCK_SIZE);

            (
                block::Mode::CBC,
                CBC::new(&iv).encrypt(&AES128, &extended_plaintext, &key),
            )
        }
    }

    #[test]
    fn detect_mode() {
        const TEST_TIMES: usize = 100;

        for _ in 0..TEST_TIMES {
            let mut snitched_mode = None;

            let detected_mode = {
                // Wrap oracle into the expected signature, saving the snitched cipher mode
                let wrapper = |plaintext: &[u8]| {
                    let (mode, ciphertext) = snitch_oracle(plaintext);
                    snitched_mode = Some(mode);
                    ciphertext
                };

                block::Mode::detect(wrapper, AES128::BLOCK_SIZE)
            };

            assert_eq!(detected_mode, snitched_mode.unwrap());
        }
    }
}

/// Byte-at-a-time ECB decryption (Simple) - http://cryptopals.com/sets/2/challenges/12
/// Byte-at-a-time ECB decryption (Harder) - http://cryptopals.com/sets/2/challenges/14
mod challenge12_14_ecb_decrypt;

/// ECB cut-and-paste - http://cryptopals.com/sets/2/challenges/13
mod challenge13_ecb_cut_and_paste;

/// PKCS#7 padding validation - http://cryptopals.com/sets/2/challenges/15
mod challenge15_pkcs7_validation {
    use pkcs7::PKCS7Error;
    use rustopals::block::pkcs7;

    #[test]
    fn correct_padding() {
        assert_eq!(
            pkcs7::unpad("ICE ICE BABY\x04\x04\x04\x04".as_bytes(), 16).unwrap(),
            "ICE ICE BABY".as_bytes()
        );
    }

    #[test]
    fn wrong_padding() {
        assert_eq!(
            pkcs7::unpad("ICE ICE BABY\x05\x05\x05\x05".as_bytes(), 16),
            Err(PKCS7Error::BadPadding)
        );

        assert_eq!(
            pkcs7::unpad("ICE ICE BABY\x01\x02\x03\x04".as_bytes(), 16),
            Err(PKCS7Error::BadPadding)
        );
    }
}

/// CBC bitflipping attacks - http://cryptopals.com/sets/2/challenges/16
mod challenge16_cbc_bitflip;
