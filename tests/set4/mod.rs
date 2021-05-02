/// Break "random access read/write" AES CTR - https://cryptopals.com/sets/4/challenges/25
mod challenge25_break_random_access_aes_ctr {
  use rustopals::block::{BlockCipher, AES128};
  use rustopals::stream::{SeekableStreamCipher, StreamCipher, CTR};

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

    let new_ciphertext = CTR::from_nonce(&AES128, &key, nonce)
      .process_from(offset, new_plaintext)
      .collect::<Vec<_>>();

    [before_new_text, &new_ciphertext, after_new_text].concat()
  }

  #[test]
  fn crack() {
    let plaintext_no_newlines = PLAINTEXT.lines().collect::<String>();
    let plaintext = base64::decode(plaintext_no_newlines).unwrap();
    let key = crate::gen_random_bytes(AES128::KEY_SIZE);
    let nonce = crate::gen_random_bytes(8);
    let ciphertext = CTR::from_nonce(&AES128, &key, &nonce)
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

// Implement a SHA-1 keyed MAC - https://cryptopals.com/sets/4/challenges/28
#[test]
fn challenge28_implement_sha1_keyed_mac() {
  use rustopals::digest::SHA1;
  use rustopals::mac::bad_mac;

  const KEY: &[u8] = b"YELLLOW SUBMARINE";
  const MESSAGE: &[u8] = b"This is a random message!";
  const TAMPERED_MESSAGE: &[u8] = b"This is a random message! And it has been tampered with.";

  assert_ne!(
    bad_mac(SHA1::new(), KEY, MESSAGE),
    bad_mac(SHA1::new(), KEY, TAMPERED_MESSAGE)
  )
}

// Break a SHA-1 keyed MAC using length extension - https://cryptopals.com/sets/4/challenges/29
mod challenge29_break_sha1_keyed_mac;
