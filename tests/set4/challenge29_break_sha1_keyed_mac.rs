mod adversary {
  use rustopals::digest::SHA1;
  use rustopals::mac::bad_mac;

  pub struct LoginSystem {
    key: Vec<u8>,
  }

  impl LoginSystem {
    pub fn new() -> LoginSystem {
      LoginSystem {
        key: crate::gen_random_bytes_between(16, 32),
      }
    }

    pub fn generate_payload(&self) -> (&[u8], [u8; 20]) {
      let plaintext =
        b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

      let mac = bad_mac(SHA1::new(), &self.key, plaintext);

      (plaintext, mac)
    }

    pub fn is_admin(&self, payload: &[u8], mac: &[u8]) -> bool {
      let calculated_mac = bad_mac(SHA1::new(), &self.key, payload);

      mac == calculated_mac && &payload[payload.len() - 11..] == b";admin=true"
    }
  }
}

#[test]
fn crack() {
  use byteorder::{BigEndian, ByteOrder};
  use rustopals::digest::{Digest, SHA1};

  let adversary = adversary::LoginSystem::new();

  let (good_payload, good_mac) = adversary.generate_payload();

  for guessed_key_length in 0..100 {
    let guessed_payload_length = guessed_key_length + good_payload.len();

    let mut ml = [0; 8];
    BigEndian::write_u64(&mut ml, 8 * guessed_payload_length as u64);

    let padding_len = 64 - ((1 + ml.len() + guessed_payload_length) % 64);

    let cracked_payload = [
      good_payload,
      &[0x80],
      &vec![0; padding_len],
      &ml,
      b";admin=true",
    ]
    .concat();

    let guessed_block_length = guessed_payload_length / 64;

    let cracked_mac =
      SHA1::new_from_hash(good_mac, 1 + guessed_block_length as u64).digest(b";admin=true");

    if adversary.is_admin(&cracked_payload, &cracked_mac) {
      return;
    }
  }

  panic!("MAC should have been cracked by now");
}
