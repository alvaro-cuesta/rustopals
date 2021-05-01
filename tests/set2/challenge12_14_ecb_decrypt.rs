const UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

mod adversary {
    use rustopals::block::{BlockCipher, AES128};

    pub trait Encryptor {
        fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
    }

    pub struct EasyOracle {
        key: Vec<u8>,
    }

    impl EasyOracle {
        pub fn new() -> EasyOracle {
            EasyOracle {
                key: crate::gen_random_bytes(AES128::KEY_SIZE),
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

            AES128.encrypt_ecb_pkcs7(&extended_plaintext, &self.key)
        }
    }

    pub struct HardOracle {
        key: Vec<u8>,
        pub prepend: Vec<u8>,
    }

    impl HardOracle {
        pub fn new(min: usize, max: usize) -> HardOracle {
            HardOracle {
                key: crate::gen_random_bytes(AES128::KEY_SIZE),
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

            AES128.encrypt_ecb_pkcs7(&extended_plaintext, &self.key)
        }
    }
}

fn discover_block_size(oracle: impl Fn(&[u8]) -> Vec<u8>) -> Option<usize> {
    let pad_size = oracle(&[]).len();

    for byte_len in (2..64).step_by(2) {
        let repeated = vec![0; pad_size + byte_len + pad_size];
        let encrypted = oracle(&repeated);

        let block_size = byte_len / 2;

        if encrypted[pad_size..pad_size + block_size]
            == encrypted[pad_size + block_size..pad_size + block_size * 2]
        {
            return Some(block_size);
        }
    }

    None
}

fn discover_prepended_length(
    oracle: impl Fn(&[u8]) -> Vec<u8>,
    block_size: usize,
) -> Option<usize> {
    use crate::gen_random_bytes;
    use rustopals::block::count_repeated;

    let empty = oracle(&[]);
    let repeats_in_empty = count_repeated(&empty, block_size);

    let random_block = gen_random_bytes(block_size);

    (0usize..empty.len() + 1)
        .filter_map(|guessed_size| {
            let mut guessed_bytes = gen_random_bytes(guessed_size);

            for _ in 0usize..100 {
                guessed_bytes.extend_from_slice(&random_block);
            }

            let encrypted = oracle(&guessed_bytes);

            let (repeats, idx) = max_continuous_repeated_blocks_and_idx(&encrypted, block_size);

            /*println!(
                "in find {} {} {} {}",
                guessed_size,
                repeats_in_empty + 2,
                repeats,
                idx
            );*/

            if repeats == 99 {
                Some(if guessed_size > 0 {
                    //println!("{:?}", encrypted.chunks(16).collect::<Vec<_>>());
                    //println!("{} {} {}", idx, block_size, guessed_size);
                    idx * block_size - guessed_size
                } else {
                    0
                })
            } else {
                None
            }
        })
        .last()
}

fn max_continuous_repeated_blocks_and_idx(input: &[u8], block_size: usize) -> (usize, usize) {
    let mut contiguous_blocks = 0usize;
    let mut max_contiguous_blocks = 1usize;

    let mut last_start_idx = 0usize;
    let mut max_contiguous_idx = 0usize;

    let mut last_block = &input[..block_size];

    for (idx, block) in input.chunks(block_size).enumerate().skip(1) {
        if block == last_block {
            contiguous_blocks += 1;

            if contiguous_blocks > max_contiguous_blocks {
                max_contiguous_blocks = contiguous_blocks;
                max_contiguous_idx = last_start_idx;
            }
        } else {
            last_start_idx = idx;
            contiguous_blocks = 0;
        }

        last_block = block;
    }

    (max_contiguous_blocks, max_contiguous_idx)
}

fn discover_payload_length_without_padding(
    oracle: impl Fn(&[u8]) -> Vec<u8>,
    block_size: usize,
) -> Option<usize> {
    let mut last_out_length = oracle(&[]).len();

    for in_length in 1..block_size + 1 {
        let input = vec![0u8; in_length];
        let out_length = oracle(&input).len();

        if out_length != last_out_length {
            return Some(last_out_length - in_length);
        }

        last_out_length = out_length;
    }

    None
}

pub fn decrypt(oracle: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    use rustopals::block::Mode;

    let block_size = discover_block_size(|input| oracle(input)).unwrap();

    if !(Mode::detect(|input| oracle(input), block_size) == Mode::ECB) {
        panic!("Oracle mode is not ECB");
    }

    let payload_length =
        discover_payload_length_without_padding(|input| oracle(input), block_size).unwrap();
    let prepeneded_length = discover_prepended_length(|input| oracle(input), block_size).unwrap();

    let mut decrypted = Vec::new();

    for decrypting_pos in prepeneded_length..payload_length {
        let cur_block = decrypting_pos / block_size;

        let plaintext = vec![0u8; block_size - 1 - decrypting_pos % block_size];
        let encrypted = oracle(&plaintext);
        let block = &encrypted[cur_block * block_size..(cur_block + 1) * block_size];

        for last_byte in 0u8..=255 {
            let new_plaintext = &[plaintext.clone(), decrypted.clone(), vec![last_byte]].concat();
            let new_encrypted = oracle(new_plaintext);
            let new_block = &new_encrypted[cur_block * block_size..(cur_block + 1) * block_size];

            if new_block == block {
                //println!("{:?}", block);
                decrypted.push(last_byte);
                break;
            } else if last_byte == 255 {
                panic!("Couldn't match!")
            }
        }
    }

    decrypted
}

mod test {
    use super::adversary::Encryptor;
    use rustopals::block::{BlockCipher, AES128};

    const TEST_MIN_PREPEND: usize = 10;
    const TEST_MAX_PREPEND: usize = 32;

    #[test]
    fn test_discover_block_size_easy() {
        let easy_oracle = super::adversary::EasyOracle::new();
        let easy_fn = |plaintext: &[u8]| easy_oracle.encrypt(plaintext);

        assert_eq!(
            super::discover_block_size(easy_fn),
            Some(AES128::BLOCK_SIZE)
        );
    }

    #[test]
    fn test_discover_block_size_hard() {
        let hard_oracle = super::adversary::HardOracle::new(TEST_MIN_PREPEND, TEST_MAX_PREPEND);
        let hard_fn = |plaintext: &[u8]| hard_oracle.encrypt(plaintext);

        assert_eq!(
            super::discover_block_size(hard_fn),
            Some(AES128::BLOCK_SIZE)
        );
    }

    /*

    #[test]
    fn test_discover_prepended_length_repeated() {
        use rustopals::block::pkcs7;

        let random_bytes = &crate::gen_random_bytes(1024);

        for i in 0..128 {
            let oracle = |input: &[u8]| {
                let value = [&vec![0u8; i], input, random_bytes].concat();

                pkcs7::pad(&value, 16)
            };

            assert_eq!(super::discover_prepended_length(oracle, 16), Some(i));
        }
    }

    */

    #[test]
    fn test_discover_prepended_length_easy() {
        let easy_oracle = super::adversary::EasyOracle::new();
        let easy_fn = |plaintext: &[u8]| easy_oracle.encrypt(plaintext);

        assert_eq!(super::discover_prepended_length(easy_fn, 16), Some(0));
    }

    #[test]
    fn test_discover_prepended_length_hard() {
        let hard_oracle = super::adversary::HardOracle::new(TEST_MIN_PREPEND, TEST_MAX_PREPEND);
        let hard_fn = |plaintext: &[u8]| hard_oracle.encrypt(plaintext);

        //println!("real prepend = {}", hard_oracle.prepend.len());

        assert_eq!(
            super::discover_prepended_length(hard_fn, 16),
            Some(hard_oracle.prepend.len())
        );
    }

    #[test]
    fn test_discover_payload_length_without_padding() {
        use rustopals::block::pkcs7;

        for i in 0..16 {
            let oracle = |input: &[u8]| {
                let value = [input, &vec![0u8; i]].concat();
                pkcs7::pad(&value, 16)
            };

            assert_eq!(
                super::discover_payload_length_without_padding(oracle, 16),
                Some(i)
            );
        }
    }

    #[test]
    fn test_discover_payload_length_without_padding_easy() {
        let easy_oracle = super::adversary::EasyOracle::new();
        let easy_fn = |plaintext: &[u8]| easy_oracle.encrypt(plaintext);

        assert_eq!(
            super::discover_payload_length_without_padding(easy_fn, 16),
            Some(138)
        );
    }

    #[test]
    fn test_discover_payload_length_without_padding_hard() {
        let hard_oracle = super::adversary::HardOracle::new(TEST_MIN_PREPEND, TEST_MAX_PREPEND);
        let hard_fn = |plaintext: &[u8]| hard_oracle.encrypt(plaintext);

        assert_eq!(
            super::discover_payload_length_without_padding(hard_fn, 16),
            Some(138 + hard_oracle.prepend.len())
        );
    }

    #[test]
    fn test_decrypt_easy() {
        let easy_oracle = super::adversary::EasyOracle::new();
        let easy_fn = |plaintext: &[u8]| easy_oracle.encrypt(plaintext);

        assert_eq!(
            super::decrypt(easy_fn),
            base64::decode(super::UNKNOWN_STRING).unwrap(),
        );
    }

    #[test]
    fn test_decrypt_hard() {
        let hard_oracle = super::adversary::HardOracle::new(TEST_MIN_PREPEND, TEST_MAX_PREPEND);
        let hard_fn = |plaintext: &[u8]| hard_oracle.encrypt(plaintext);

        assert_eq!(
            super::decrypt(hard_fn),
            base64::decode(super::UNKNOWN_STRING).unwrap(),
        );
    }
}
