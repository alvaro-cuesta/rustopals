/// Break "random access read/write" AES CTR - https://cryptopals.com/sets/4/challenges/25
mod challenge25_break_random_access_aes_ctr {
  use rustopals::block::{aes128, Cipher as BlockCipher};
  use rustopals::stream::{ctr, Cipher as StreamCipher, SeekableCipher as SeekableStreamCipher};

  const PLAINTEXT: &str = include_str!("25.txt");

  fn edit(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    offset: usize,
    new_plaintext: &[u8],
  ) -> Vec<u8> {
    let before_new_text = &ciphertext[..offset];
    let after_new_text = &ciphertext[offset + 1..];

    let new_ciphertext = ctr::Cipher::from_nonce(&aes128::Cipher, &key, nonce)
      .process_from(offset, new_plaintext)
      .collect::<Vec<_>>();

    [before_new_text, &new_ciphertext, after_new_text].concat()
  }

  #[test]
  fn crack() {
    let plaintext_no_newlines = PLAINTEXT.lines().collect::<String>();
    let plaintext = base64::decode(plaintext_no_newlines).unwrap();
    let key = crate::gen_random_bytes(aes128::Cipher::KEY_SIZE);
    let nonce = crate::gen_random_bytes(8);
    let ciphertext = ctr::Cipher::from_nonce(&aes128::Cipher, &key, &nonce)
      .process(&plaintext)
      .collect::<Vec<_>>();

    let mut recovered_plaintext = vec![0; plaintext.len()];

    'offset: for offset in 0..ciphertext.len() {
      for byte in u8::min_value()..=u8::max_value() {
        let new_ciphertext = edit(&ciphertext, &key, &nonce, offset, &[byte]);

        if new_ciphertext == ciphertext {
          recovered_plaintext[offset] = byte;
          continue 'offset;
        }
      }

      unreachable!("A matching byte should have been found by now")
    }

    assert_eq!(recovered_plaintext, plaintext)
  }
}

/// CTR bitflipping - https://cryptopals.com/sets/4/challenges/26
mod challenge26_ctr_bitflip;

// Recover the key from CBC with IV=Key - https://cryptopals.com/sets/4/challenges/27
mod challenge27_recover_iv_as_key;
