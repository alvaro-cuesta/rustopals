use rustopals::util::NaiveTextScorer;

#[test]
/// Convert hex to base64 - https://cryptopals.com/sets/1/challenges/1
fn challenge1_hex_to_base64() {
    use rustopals::util::iter::bytes_from_hex;

    const INPUT: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const EXPECTED: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let result = ::base64::encode(
        &bytes_from_hex(INPUT)
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    );

    assert_eq!(result, EXPECTED);
}

#[test]
/// Fixed XOR - https://cryptopals.com/sets/1/challenges/2
fn challenge2_fixed_xor() {
    use rustopals::util::iter::{bytes_from_hex, ToHexable, Xorable};

    const INPUT_A: &str = "1c0111001f010100061a024b53535009181c";
    const INPUT_B: &str = "686974207468652062756c6c277320657965";
    const EXPECTED: &str = "746865206b696420646f6e277420706c6179";

    let bytes_a = bytes_from_hex(INPUT_A).map(|x| x.unwrap());
    let bytes_b = bytes_from_hex(INPUT_B).map(|x| x.unwrap());

    let result = bytes_a.xor(bytes_b).to_hex();

    assert_eq!(result, EXPECTED);
}

#[test]
/// Single-byte XOR cipher - https://cryptopals.com/sets/1/challenges/3
fn challenge3_single_byte_xor_cipher() {
    use rustopals::stream::SingleXORCipher;
    use rustopals::util::iter::bytes_from_hex;

    const INPUT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const EXPECTED_KEY: u8 = 88;
    const EXPECTED_PLAINTEXT: &str = "Cooking MC's like a pound of bacon";

    let input = bytes_from_hex(INPUT)
        .map(|x| x.unwrap())
        .collect::<Vec<_>>();

    let (key, plaintext) = SingleXORCipher::<u8>::crack(&NaiveTextScorer, &input).unwrap();

    assert_eq!(key, EXPECTED_KEY);
    assert_eq!(plaintext, EXPECTED_PLAINTEXT);
}

#[test]
/// Detect single-character XOR - https://cryptopals.com/sets/1/challenges/4
fn challenge4_detect_single_byte_xor() {
    use rustopals::stream::SingleXORCipher;
    use rustopals::util::iter::bytes_from_hex;

    const INPUT: &str = include_str!("4.txt");
    const EXPECTED_POS: usize = 170;
    const EXPECTED_KEY: u8 = 53;
    const EXPECTED_PLAINTEXT: &str = "Now that the party is jumping\n";

    let input = INPUT
        .lines()
        .map(bytes_from_hex)
        .map(Iterator::collect::<Result<Vec<_>, _>>)
        .map(Result::unwrap)
        .collect::<Vec<_>>();

    let input_slices = input.iter().map(Vec::as_slice).collect::<Vec<_>>();

    let (pos, key, plaintext) =
        SingleXORCipher::<u8>::detect(&NaiveTextScorer, &input_slices).unwrap();

    assert_eq!(pos, EXPECTED_POS);
    assert_eq!(key, EXPECTED_KEY);
    assert_eq!(plaintext, EXPECTED_PLAINTEXT);
}

#[test]
/// Implement repeating-key XOR - https://cryptopals.com/sets/1/challenges/5
fn challenge5_implement_repeating_key_xor() {
    use rustopals::stream::{RepeatingXORCipher, StreamCipher};
    use rustopals::util::iter::ToHexable;

    const PLAINTEXT: &[u8] = b"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    const KEY: &[u8] = b"ICE";
    const EXPECTED: &str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    let result = RepeatingXORCipher(KEY).process(PLAINTEXT).to_hex();

    assert_eq!(result, EXPECTED);
}

/// Break repeating-key XOR - https://cryptopals.com/sets/1/challenges/6
#[test]
fn challenge6_repeating_key_xor() {
    use rustopals::stream::{RepeatingXORCipher, StreamCipher};

    const CIPHERTEXT: &str = include_str!("6.txt");
    const MAX_KEYSIZE_GUESS: usize = 40;

    const EXPECTED_KEY: &[u8] = b"Terminator X: Bring the noise";
    const EXPECTED_PLAINTEXT: &[u8] = include_bytes!("6.solution.txt");

    let ciphertext_no_newlines = CIPHERTEXT.lines().collect::<String>();

    let ciphertext = ::base64::decode(&ciphertext_no_newlines).unwrap();

    let guessed_keysize =
        RepeatingXORCipher::<u8>::guess_keysize(&ciphertext, MAX_KEYSIZE_GUESS).unwrap();

    assert_eq!(guessed_keysize, EXPECTED_KEY.len());

    let guessed_key =
        RepeatingXORCipher::<u8>::guess_key(&NaiveTextScorer, &ciphertext, guessed_keysize);

    assert_eq!(guessed_key, EXPECTED_KEY);

    let plaintext = RepeatingXORCipher(&guessed_key)
        .process(ciphertext)
        .collect::<Vec<_>>();

    assert_eq!(plaintext, EXPECTED_PLAINTEXT);
}

/// AES in ECB mode - https://cryptopals.com/sets/1/challenges/7
mod challenge7_aes_ecb {
    use rustopals::block::{BlockMode, AES128, ECB};

    const CIPHERTEXT: &str = include_str!("7.txt");
    const PLAINTEXT: &[u8] = include_bytes!("7.solution.txt");
    const KEY: &[u8] = b"YELLOW SUBMARINE";

    #[test]
    fn encrypt() {
        let ciphertext_no_newlines = CIPHERTEXT.lines().collect::<String>();
        let expected_ciphertext = ::base64::decode(&ciphertext_no_newlines).unwrap();

        assert_eq!(
            ECB.encrypt_impl(&AES128, PLAINTEXT, KEY),
            expected_ciphertext,
        );
    }

    #[test]
    fn decrypt() {
        let ciphertext_no_newlines = CIPHERTEXT.lines().collect::<String>();
        let ciphertext = ::base64::decode(&ciphertext_no_newlines).unwrap();
        let decrypted = ECB.decrypt_impl(&AES128, &ciphertext, KEY);

        assert_eq!(decrypted, PLAINTEXT);
    }
}

/// Detect AES in ECB mode - https://cryptopals.com/sets/1/challenges/8
#[test]
fn challenge8_detect_ecb() {
    use rustopals::block::{BlockCipher, AES128, ECB};
    use rustopals::util::iter::bytes_from_hex;

    const INPUT: &str = include_str!("8.txt");
    const EXPECTED_RESULT: usize = 132;

    let (line_num, _) = INPUT
        .lines()
        .enumerate()
        .max_by_key(|&(_, line)| {
            let bytes = bytes_from_hex(line).collect::<Result<Vec<_>, _>>().unwrap();

            ECB::score(&bytes, AES128::BLOCK_SIZE)
        })
        .unwrap();

    assert_eq!(line_num, EXPECTED_RESULT);
}
