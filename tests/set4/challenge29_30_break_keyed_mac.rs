use rustopals::digest::{Digest, ExtensibleDigest, MD4, SHA1};

const TARGET: &[u8] = b";admin=true";

mod adversary {
    use super::TARGET;
    use rustopals::digest::Digest;
    use rustopals::mac::bad_mac;
    use std::marker::PhantomData;

    pub struct LoginSystem<D: Digest + Default> {
        key: Vec<u8>,
        phantom: PhantomData<D>,
    }

    impl<'a, D> LoginSystem<D>
    where
        D: Digest + Default,
    {
        pub fn new() -> LoginSystem<D> {
            LoginSystem {
                key: crate::gen_random_bytes_between(16, 32),
                phantom: PhantomData,
            }
        }

        pub fn generate_payload(&self) -> (&[u8], D::Output) {
            let plaintext =
                b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

            let mac = bad_mac(D::default(), &self.key, plaintext);

            (plaintext, mac)
        }

        pub fn is_admin(&self, payload: &[u8], mac: &[u8]) -> bool {
            let calculated_mac = bad_mac(D::default(), &self.key, payload);

            (mac == calculated_mac.as_ref()) && (&payload[payload.len() - 11..] == TARGET)
        }
    }
}

fn crack<D>()
where
    D: Digest + ExtensibleDigest + Default,
    D::Output: Copy,
{
    let adversary = adversary::LoginSystem::<D>::new();

    let (good_payload, good_mac) = adversary.generate_payload();

    for guessed_key_length in 0..100 {
        let guessed_payload_length = guessed_key_length + good_payload.len();

        let (cracked_digest, cracked_padding) =
            <D as ExtensibleDigest>::extend_digest(good_mac, guessed_payload_length);

        let cracked_mac = cracked_digest.digest(TARGET);
        let cracked_payload = [good_payload, &cracked_padding, TARGET].concat();

        if adversary.is_admin(&cracked_payload, cracked_mac.as_ref()) {
            return;
        }
    }

    panic!("MAC should have been cracked by now");
}

#[test]
fn crack_sha1() {
    crack::<SHA1>()
}

#[test]
fn crack_md4() {
    crack::<MD4>()
}
