use rustopals::block::{BlockCipher, AES128};

const STRINGS: &str = include_str!("17.txt");

mod adversary {
    use rustopals::block::{BlockCipher, BlockMode, AES128, CBC};
    use rustopals::util::generate_bytes;

    pub struct PaddingOracle {
        key: Vec<u8>,
    }

    impl PaddingOracle {
        pub fn new() -> PaddingOracle {
            PaddingOracle {
                key: generate_bytes(AES128::BLOCK_SIZE),
            }
        }

        pub fn get_string(&self) -> (Vec<u8>, Vec<u8>) {
            use rand::seq::IteratorRandom;
            use rand::thread_rng;

            let mut rng = thread_rng();
            let chosen_string = super::STRINGS.lines().choose(&mut rng).unwrap();

            let iv = generate_bytes(AES128::BLOCK_SIZE);

            let encrypted =
                CBC::new(&iv).encrypt(&AES128, &base64::decode(chosen_string).unwrap(), &self.key);

            (encrypted, iv)
        }

        pub fn is_correct_padding(&self, ciphertext: &[u8], iv: &[u8]) -> bool {
            CBC::new(iv).decrypt(&AES128, ciphertext, &self.key).is_ok()
        }
    }
}

fn decrypt_block(oracle: &adversary::PaddingOracle, block: &[u8], iv: &[u8]) -> Vec<u8> {
    use num_traits::Bounded;
    use rustopals::util::iter::Xorable;

    let mut known: Vec<u8> = vec![];

    'next: while known.len() != 16 {
        for possible_byte in 0_u8..=Bounded::max_value() {
            let mut my_block = vec![0; AES128::BLOCK_SIZE - known.len() - 1];
            my_block.push(possible_byte);

            let padding_len_goal = (known.len() + 1) as u8;

            let masked_known = known
                .iter()
                .xor(vec![padding_len_goal; known.len()].iter())
                .collect::<Vec<u8>>();

            my_block.extend_from_slice(&masked_known);

            let my_iv = my_block.iter().xor(iv.iter()).collect::<Vec<u8>>();

            if oracle.is_correct_padding(block, &my_iv) {
                if !known.is_empty() {
                    known.insert(0, possible_byte ^ padding_len_goal);
                    continue 'next;
                }

                for corrupt_len in 1..=AES128::BLOCK_SIZE {
                    let corrupting = vec![1; corrupt_len];
                    let keeping = vec![0_u8; AES128::BLOCK_SIZE - (corrupt_len as usize)];
                    let mask = [corrupting, keeping].concat();

                    let masked_iv = my_iv.iter().xor(mask.iter()).collect::<Vec<u8>>();

                    let result = oracle.is_correct_padding(block, &masked_iv);

                    if !result {
                        let length = (AES128::BLOCK_SIZE - corrupt_len + 1) as u8;
                        for _ in 0..length {
                            known.insert(0, possible_byte ^ length);
                        }
                        continue 'next;
                    }
                }
            }
        }
    }

    known
}

mod test {
    #[test]
    fn padding_oracle() {
        use rustopals::block::{pkcs7, BlockCipher, AES128};

        let oracle = super::adversary::PaddingOracle::new();

        let (encrypted, iv) = oracle.get_string();

        let blocks = encrypted.chunks(AES128::BLOCK_SIZE).collect::<Vec<_>>();

        let mut ivs = vec![iv.as_slice()];
        ivs.extend_from_slice(&blocks);

        let bytes = blocks
            .iter()
            .enumerate()
            .map(|(idx, &block)| super::decrypt_block(&oracle, block, ivs[idx]))
            .collect::<Vec<_>>()
            .concat();

        let unpadded = pkcs7::unpad(&bytes, AES128::BLOCK_SIZE as u8).unwrap();

        let in_string = super::STRINGS
            .lines()
            .map(|x| base64::decode(x).unwrap())
            .find(|x| x == unpadded);

        if in_string == None {
            panic!("Decrypted is not found in STRINGS")
        }
    }
}
