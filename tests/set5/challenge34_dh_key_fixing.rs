use num_bigint::BigUint;
use num_traits::Zero;
use rustopals::block::{BlockCipher, BlockMode, AES128, CBC};
use rustopals::digest::{Digest, SHA1};
use rustopals::key_exchange::dh::{DHOffer, NIST_BASE, NIST_MODULUS};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::thread;

enum Message {
    Offer {
        modulus: BigUint,
        base: BigUint,
        public_key: BigUint,
    },
    Response {
        public_key: BigUint,
    },
    Message {
        message: Vec<u8>,
        iv: Vec<u8>,
    },
}

fn alice(tx: SyncSender<Message>, rx: Receiver<Message>) -> Vec<u8> {
    // (1) A->B -- Send "p", "g", "A"
    let bytes = base64::decode(NIST_MODULUS).unwrap();

    let modulus = BigUint::from_bytes_be(&bytes);
    let base = BigUint::from(NIST_BASE);

    let dh_offer = DHOffer::new_custom(modulus.clone(), &base);

    tx.send(Message::Offer {
        modulus,
        base,
        public_key: dh_offer.get_public().clone(),
    })
    .unwrap();

    // (2) B->A -- Send "B"
    let their_public = match rx.recv().unwrap() {
        Message::Response { public_key } => public_key,
        _ => panic!("Expected `Message::Response` on Alice"),
    };

    let key_material = dh_offer
        .establish(&their_public)
        .expect("Detected an error!")
        .to_key_material::<SHA1>();

    // (3) A->B -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    let my_message = crate::gen_random_bytes_between(123, 456);
    let my_iv = crate::gen_random_bytes(AES128::BLOCK_SIZE);
    let my_encrypted_message = CBC::new(&my_iv).encrypt(&AES128, &my_message, &key_material[0..16]);

    tx.send(Message::Message {
        message: my_encrypted_message,
        iv: my_iv,
    })
    .unwrap();

    // (4) B->A -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    let (their_ecrypted_message, their_iv) = match rx.recv().unwrap() {
        Message::Message { message, iv } => (message, iv),
        _ => panic!("Expected `Message::Message` on Alice"),
    };

    let their_message = CBC::new(&their_iv)
        .decrypt(&AES128, &their_ecrypted_message, &key_material[0..16])
        .unwrap();

    assert_eq!(my_message, their_message); // Check that echo is OK!

    // Ensure communication is dropped
    drop(rx);
    drop(tx);

    // Return to double-check later
    my_message
}

fn bob(tx: SyncSender<Message>, rx: Receiver<Message>) {
    // (1) A->B -- Send "p", "g", "A"
    let (modulus, base, their_public) = match rx.recv().unwrap() {
        Message::Offer {
            modulus,
            base,
            public_key,
        } => (modulus, base, public_key),
        _ => panic!("Expected `Message::Offer` on Bob"),
    };

    // (2) B->A -- Send "B"
    let dh_offer = DHOffer::new_custom(modulus, &base);

    tx.send(Message::Response {
        public_key: dh_offer.get_public().clone(),
    })
    .unwrap();

    let key_material = dh_offer
        .establish(&their_public)
        .expect("Detected an error!")
        .to_key_material::<SHA1>();

    // (3) A->B -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    let (their_ecrypted_message, their_iv) = match rx.recv().unwrap() {
        Message::Message { message, iv } => (message, iv),
        _ => panic!("Expected `Message::Message` on Bob"),
    };

    let their_message = CBC::new(&their_iv)
        .decrypt(&AES128, &their_ecrypted_message, &key_material[0..16])
        .unwrap();

    // (4) B->A -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    let my_iv = crate::gen_random_bytes(AES128::BLOCK_SIZE);
    let my_encrypted_message =
        CBC::new(&my_iv).encrypt(&AES128, &their_message, &key_material[0..16]);

    tx.send(Message::Message {
        message: my_encrypted_message,
        iv: my_iv,
    })
    .unwrap();

    // Ensure communication is dropped
    drop(rx);
    drop(tx);
}

fn eve(
    alice_tx: SyncSender<Message>,
    alice_rx: Receiver<Message>,
    bob_tx: SyncSender<Message>,
    bob_rx: Receiver<Message>,
) -> Vec<u8> {
    // (1) A->M -- Send "p", "g", "A"
    //     Notice this isn't a regular MITM since we're ignoring Alice's PK
    let (modulus, base, _alice_public) = match alice_rx.recv().unwrap() {
        Message::Offer {
            modulus,
            base,
            public_key,
        } => (modulus, base, public_key),
        _ => panic!("Expected `Message::Offer` on Eve"),
    };

    // (2) M->B -- Send "p", "g", "p"
    bob_tx
        .send(Message::Offer {
            modulus: modulus.clone(),
            base,
            public_key: modulus.clone(),
        })
        .unwrap();

    // (3) B->M -- Send "B"
    //     Notice this isn't a regular MITM since we're ignoring Bob's PK
    let _bob_public = match bob_rx.recv().unwrap() {
        Message::Response { public_key } => public_key,
        _ => panic!("Expected `Message::Response` on Eve"),
    };

    // (4) M->A -- Send "p"
    alice_tx
        .send(Message::Response {
            public_key: modulus,
        })
        .unwrap();

    // (5) A->M -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    let (alice_encrypted_message, alice_iv) = match alice_rx.recv().unwrap() {
        Message::Message { message, iv } => (message, iv),
        _ => panic!("Expected `Message::Message` from Alice on Eve"),
    };

    // (6) M->B -- Relay that to B
    bob_tx
        .send(Message::Message {
            message: alice_encrypted_message.clone(),
            iv: alice_iv.clone(),
        })
        .unwrap();

    // (7) B->M -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    let (bob_encrypted_message, bob_iv) = match bob_rx.recv().unwrap() {
        Message::Message { message, iv } => (message, iv),
        _ => panic!("Expected `Message::Message` from Bob on Eve"),
    };

    // (8) M->A -- Relay that to A
    alice_tx
        .send(Message::Message {
            message: bob_encrypted_message.clone(),
            iv: bob_iv.clone(),
        })
        .unwrap();

    // Okay, let's see if your nefarious deeds were successful...
    let expected_key_material = &SHA1::new().digest(&BigUint::zero().to_bytes_be())[0..16];

    let alice_message = CBC::new(&alice_iv)
        .decrypt(&AES128, &alice_encrypted_message, expected_key_material)
        .unwrap();
    let bob_message = CBC::new(&bob_iv)
        .decrypt(&AES128, &bob_encrypted_message, expected_key_material)
        .unwrap();

    assert_eq!(alice_message, bob_message);

    // Ensure communication is dropped
    drop(alice_tx);
    drop(alice_rx);
    drop(bob_tx);
    drop(bob_rx);

    // Return to double-check later
    alice_message
}

// This test passes if non-MITM'd communication works
#[test]
fn test_normal_operation() {
    let (alice_tx, bob_rx) = sync_channel::<Message>(0);
    let (bob_tx, alice_rx) = sync_channel::<Message>(0);

    let alice_thread = thread::spawn(move || alice(alice_tx, alice_rx));
    let bob_thread = thread::spawn(move || bob(bob_tx, bob_rx));

    alice_thread.join().unwrap();
    bob_thread.join().unwrap();
}

// This test passes if nobody noticed the MITM
#[test]
fn test_key_fixing() {
    let (alice_tx, eve_alice_rx) = sync_channel::<Message>(0);
    let (eve_alice_tx, alice_rx) = sync_channel::<Message>(0);
    let (eve_bob_tx, bob_rx) = sync_channel::<Message>(0);
    let (bob_tx, eve_bob_rx) = sync_channel::<Message>(0);

    let alice_thread = thread::spawn(move || alice(alice_tx, alice_rx));
    let bob_thread = thread::spawn(move || bob(bob_tx, bob_rx));
    let eve_thread = thread::spawn(move || eve(eve_alice_tx, eve_alice_rx, eve_bob_tx, eve_bob_rx));

    let alice_message = alice_thread.join().unwrap();
    bob_thread.join().unwrap();
    let eve_message = eve_thread.join().unwrap();

    // Double check
    assert_eq!(alice_message, eve_message);
}
