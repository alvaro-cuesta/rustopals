#![allow(clippy::many_single_char_names)]

use num_bigint::{BigUint, RandBigInt};
use once_cell::sync::Lazy;
use rand::prelude::SliceRandom;
use rand::{thread_rng, Rng};
use rustopals::digest::{Digest, SHA256};
use rustopals::key_exchange::dh::NIST_MODULUS;
use rustopals::mac::hmac;

static G: Lazy<BigUint> = Lazy::new(|| BigUint::from(2_usize));

const EMAIL: &[u8] = b"will@example.com";
const PASSWORD: &[u8] = b"In west Philadelphia, born and raised";

struct Server {
    salt: Vec<u8>,
    v: BigUint,
    private_key: BigUint,
    public_key: BigUint,
    u: u128,
}

impl Server {
    pub fn new() -> Server {
        let salt = crate::gen_random_bytes(32);

        let x_h = SHA256::new().chain(&salt).chain(PASSWORD).finalize();
        let x = BigUint::from_bytes_be(&x_h);

        let v = G.modpow(&x, &NIST_MODULUS);

        let mut rng = thread_rng();

        let private_key = rng.gen_biguint_range(&BigUint::from(0_usize), &NIST_MODULUS);
        let public_key = G.modpow(&private_key, &NIST_MODULUS);

        let u = rng.gen();

        Server {
            salt,
            v,
            private_key,
            public_key,
            u,
        }
    }

    pub fn check_client_mac(
        &self,
        email: &[u8],
        client_public_key: &BigUint,
        their_mac: &<SHA256 as Digest>::Output,
    ) -> bool {
        if email != EMAIL {
            return false;
        }

        let s = (client_public_key * self.v.modpow(&BigUint::from(self.u), &NIST_MODULUS))
            .modpow(&self.private_key, &NIST_MODULUS);
        let k = SHA256::digest(&s.to_bytes_be());

        let my_mac = hmac::<SHA256>(&k, &self.salt);

        their_mac == &my_mac
    }

    fn get_salt(&self) -> &[u8] {
        &self.salt
    }

    const fn get_public(&self) -> &BigUint {
        &self.public_key
    }

    const fn get_u(&self) -> u128 {
        self.u
    }
}

struct Client {
    private_key: BigUint,
    public_key: BigUint,
}

impl Client {
    pub fn new() -> Client {
        let private_key = thread_rng().gen_biguint_range(&BigUint::from(0_usize), &NIST_MODULUS);
        let public_key = G.modpow(&private_key, &NIST_MODULUS);

        Client {
            private_key,
            public_key,
        }
    }

    pub fn get_data_for_server(
        self,
        password: &[u8],
        salt: &[u8],
        server_public_key: &BigUint,
        u: u128,
    ) -> (BigUint, <SHA256 as Digest>::Output) {
        let x_h = SHA256::new().chain(salt).chain(password).finalize();
        let x = BigUint::from_bytes_be(&x_h);

        let s = server_public_key.modpow(&(self.private_key + BigUint::from(u) * x), &NIST_MODULUS);
        let k = SHA256::digest(&s.to_bytes_be());

        let mac = hmac::<SHA256>(&k, salt);

        (self.public_key, mac)
    }
}

#[test]
fn test_normal_operation_ok() {
    let server = Server::new();
    let client = Client::new();

    let salt = server.get_salt();
    let server_public_key = server.get_public();
    let server_u = server.get_u();

    let (client_public_key, client_mac) =
        client.get_data_for_server(PASSWORD, salt, server_public_key, server_u);

    assert!(server.check_client_mac(EMAIL, &client_public_key, &client_mac))
}

#[test]
fn test_normal_operation_fail() {
    let server = Server::new();
    let client = Client::new();

    let salt = server.get_salt();
    let server_public_key = server.get_public();
    let server_u = server.get_u();

    let (client_public_key, client_mac) =
        client.get_data_for_server(b"NOT QUITE THE PASSWORD", salt, server_public_key, server_u);

    assert!(!server.check_client_mac(EMAIL, &client_public_key, &client_mac))
}

// We send an empty salt a u = 1 for convenience, we also send G as the
// server's public key so that:
//
// client_s = server_public_key.modpow(client_private_key + u * x, n)
// ->
// client_s = g.modpow(client_private_key + x, n)
//
// The server knows `x` but we don't have `client_private_key`. Fortunately
// the client sends us `client_public_key`:
//
// client_public_key = g.modpow(client_private_key, n)
//
// This means that server can calculate `client_s` like this:
//
// client_s = client_public_key * g.modpow(client_private_key + x, n)

const POSSIBLE_PASSWORDS: &[&[u8]] = &[b"hello", b"world", b"just", b"a few", b"examples"];

static DICTIONARY: Lazy<Vec<(&[u8], BigUint)>> = Lazy::new(|| {
    POSSIBLE_PASSWORDS
        .iter()
        .map(|&password| {
            let x_h = SHA256::digest(password);
            let x = BigUint::from_bytes_be(&x_h);

            (password, G.modpow(&x, &NIST_MODULUS))
        })
        .collect()
});

const CRACK_SALT: &[u8] = &[];
const CRACK_U: u128 = 1_u128;

#[test]
fn test_offline_dictionary() {
    let client = Client::new();

    let client_password = *POSSIBLE_PASSWORDS.choose(&mut thread_rng()).unwrap();

    let (client_public_key, client_mac) =
        client.get_data_for_server(client_password, CRACK_SALT, &G, CRACK_U);

    for (password, half_s) in &*DICTIONARY {
        let crack_s = (&client_public_key * half_s) % &*NIST_MODULUS;
        let crack_k = SHA256::digest(&crack_s.to_bytes_be());
        let crack_mac = hmac::<SHA256>(&crack_k, CRACK_SALT);

        if crack_mac == client_mac {
            assert_eq!(&client_password, password);
            return; // Found!
        }
    }

    panic!("Password should have been found by now")
}
