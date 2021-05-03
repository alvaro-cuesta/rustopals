mod adversary {
    use std::collections::HashMap;

    use rustopals::block::{BlockCipher, BlockMode, AES128, ECB};

    pub struct LoginSystem {
        key: Vec<u8>,
    }

    impl LoginSystem {
        pub fn new() -> LoginSystem {
            LoginSystem {
                key: crate::gen_random_bytes(AES128::BLOCK_SIZE),
            }
        }

        pub fn generate_payload(&self, email: &str) -> Vec<u8> {
            ECB.encrypt(&AES128, profile_for(email).as_bytes(), &self.key)
        }

        pub fn is_admin(&self, payload: &[u8]) -> bool {
            use std::str;

            match ECB.decrypt(&AES128, payload, &self.key) {
                Ok(decrypted) => match str::from_utf8(&decrypted) {
                    Ok(string) => parse(string)["role"] == "admin",
                    Err(_) => false,
                },
                Err(_) => false,
            }
        }
    }

    /// Parse a querystring-like string into a `K -> V` mapping.
    fn parse(data: &str) -> HashMap<&str, &str> {
        data.split('&')
            .map(|part| {
                let pair = part.splitn(2, '=').collect::<Vec<_>>();
                (pair[0], if pair.len() == 2 { pair[1] } else { "true" })
            })
            .collect()
    }

    /// Build a user profile for a certain email.
    fn profile_for(email: &str) -> String {
        let sanitized = email.replace("=", "").replace("&", "");

        ["email=", &sanitized, "&uid=10&role=user"].concat()
    }

    #[cfg(test)]
    mod test {
        #[test]
        fn parse() {
            use std::collections::HashMap;

            let expected = [
                ("foo", "bar"),
                ("baz", "qux"),
                ("zap", "zazzle"),
                ("inga", "true"),
            ]
            .iter()
            .copied()
            .collect::<HashMap<_, _>>();

            assert_eq!(super::parse("foo=bar&baz=qux&zap=zazzle&inga"), expected)
        }

        #[test]
        fn profile_for() {
            assert_eq!(
                super::profile_for("foo@bar.com"),
                "email=foo@bar.com&uid=10&role=user"
            );

            assert_eq!(
                super::profile_for("f=o&o@b==&ar.com==&"),
                "email=foo@bar.com&uid=10&role=user"
            );
        }
    }
}

/*
 *
 */

fn crack(login: &adversary::LoginSystem) -> Vec<u8> {
    // CUT
    // 0123456789abcdef0123456789abcdef0123456789abcdef
    //                 ----------------
    // email=0000000000admin___________&uid=10&role=user (where _ is pkcs7 padding)
    let admin =
        login.generate_payload("0000000000admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b");
    let admin_bytes = &admin[0x10..0x20];

    // PASTE
    // 0123456789abcdef0123456789abcdef0123456789abcdef
    //                                 ----------------
    // email=trust@mee.com&uid=10&role=user____________
    let mut my_email = login.generate_payload("trust@mee.com");
    my_email.truncate(0x20);
    my_email.extend_from_slice(admin_bytes);

    my_email
}

#[cfg(test)]
mod test {
    #[test]
    fn crack() {
        let login = super::adversary::LoginSystem::new();

        assert!(login.is_admin(&super::crack(&login)))
    }
}
