#![allow(clippy::many_single_char_names)]

use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use rustopals::digest::{Digest, SHA256};
use rustopals::key_exchange::dh::NIST_MODULUS;
use rustopals::mac::hmac;

const EMAIL: &[u8] = b"will@example.com";
const PASSWORD: &[u8] = b"In west Philadelphia, born and raised";

struct Server {
    salt: Vec<u8>,
    v: BigUint,
    private_key: BigUint,
    public_key: BigUint,
}

impl Server {
    fn new() -> Server {
        let n_bytes = base64::decode(NIST_MODULUS).unwrap();
        let n = BigUint::from_bytes_be(&n_bytes);
        let g = BigUint::from(2_usize);
        let k = BigUint::from(3_usize);

        let salt = crate::gen_random_bytes(32);

        let x_h = SHA256::new().chain(&salt).chain(PASSWORD).finalize();
        let x = BigUint::from_bytes_be(&x_h);

        let v = g.modpow(&x, &n);

        let private_key = thread_rng().gen_biguint_range(&BigUint::from(0_usize), &n);
        let public_key = k * v.clone() + g.modpow(&private_key, &n);

        Server {
            salt,
            v,
            private_key,
            public_key,
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

        let n_bytes = base64::decode(NIST_MODULUS).unwrap();
        let n = BigUint::from_bytes_be(&n_bytes);

        let u_h = SHA256::new()
            .chain(&client_public_key.to_bytes_be())
            .chain(&self.public_key.to_bytes_be())
            .finalize();
        let u = BigUint::from_bytes_be(&u_h);

        let s = (client_public_key.clone() * self.v.clone().modpow(&u, &n))
            .modpow(&self.private_key, &n);
        let k = SHA256::digest(&s.to_bytes_be());

        let my_mac = &hmac::<SHA256>(&k, &self.salt);

        their_mac == my_mac
    }

    fn get_salt(&self) -> &[u8] {
        &self.salt
    }

    const fn get_public(&self) -> &BigUint {
        &self.public_key
    }
}

struct Client {
    private_key: BigUint,
    public_key: BigUint,
}

impl Client {
    fn new() -> Client {
        let n_bytes = base64::decode(NIST_MODULUS).unwrap();
        let n = BigUint::from_bytes_be(&n_bytes);
        let g = BigUint::from(2_usize);

        let private_key = thread_rng().gen_biguint_range(&BigUint::from(0_usize), &n);
        let public_key = g.modpow(&private_key, &n);

        Client {
            private_key,
            public_key,
        }
    }

    fn get_data_for_server(
        self,
        password: &[u8],
        salt: &[u8],
        server_public_key: &BigUint,
    ) -> (BigUint, <SHA256 as Digest>::Output) {
        let n_bytes = base64::decode(NIST_MODULUS).unwrap();
        let n = BigUint::from_bytes_be(&n_bytes);
        let g = BigUint::from(2_usize);
        let k = BigUint::from(3_usize);

        let u_h = SHA256::new()
            .chain(&self.public_key.to_bytes_be())
            .chain(&server_public_key.to_bytes_be())
            .finalize();
        let u = BigUint::from_bytes_be(&u_h);

        let x_h = SHA256::new().chain(salt).chain(password).finalize();
        let x = BigUint::from_bytes_be(&x_h);

        let s = (server_public_key.clone() - (k * g.modpow(&x, &n)) % &n)
            .modpow(&(self.private_key.clone() + u * x), &n);
        let k = SHA256::digest(&s.to_bytes_be());

        (self.public_key, hmac::<SHA256>(&k, salt))
    }
}

#[test]
fn test_normal_operation_ok() {
    let server = Server::new();
    let client = Client::new();

    let salt = server.get_salt();
    let server_public_key = server.get_public();

    let (client_public_key, client_mac) =
        client.get_data_for_server(PASSWORD, salt, server_public_key);

    assert!(server.check_client_mac(EMAIL, &client_public_key, &client_mac))
}

#[test]
fn test_normal_operation_fail() {
    let server = Server::new();
    let client = Client::new();

    let salt = server.get_salt();
    let server_public_key = server.get_public();

    let (client_public_key, client_mac) =
        client.get_data_for_server(b"NOT THE CORRECT PASSWORD", salt, server_public_key);

    assert!(!server.check_client_mac(EMAIL, &client_public_key, &client_mac))
}

#[test]
fn test_zero_key() {
    let server = Server::new();
    let zero = BigUint::from(0_usize);
    assert!(server.check_client_mac(
        EMAIL,
        &zero,
        &hmac::<SHA256>(&SHA256::digest(&zero.to_bytes_be()), server.get_salt())
    ))
}

#[test]
fn test_n_key() {
    let n_bytes = base64::decode(NIST_MODULUS).unwrap();
    let n = BigUint::from_bytes_be(&n_bytes);

    let server = Server::new();
    let zero = BigUint::from(0_usize);

    assert!(server.check_client_mac(
        EMAIL,
        &n,
        &hmac::<SHA256>(&SHA256::digest(&zero.to_bytes_be()), server.get_salt())
    ));

    assert!(server.check_client_mac(
        EMAIL,
        &(BigUint::from(2_usize) * n),
        &hmac::<SHA256>(&SHA256::digest(&zero.to_bytes_be()), server.get_salt())
    ));
}
