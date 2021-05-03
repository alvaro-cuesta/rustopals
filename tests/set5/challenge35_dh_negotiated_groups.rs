use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::thread;

use num_bigint::BigUint;
use rustopals::block::{BlockCipher, BlockMode, AES128, CBC};
use rustopals::digest::{Digest, SHA1};
use rustopals::key_exchange::dh::{DHOffer, NIST_BASE, NIST_MODULUS};

enum Message {
    Negotiate { modulus: BigUint, base: BigUint },
    Accept,
    Offer { public_key: BigUint },
    Response { public_key: BigUint },
    Message { message: Vec<u8>, iv: Vec<u8> },
}

fn alice(tx: SyncSender<Message>, rx: Receiver<Message>) -> Vec<u8> {
    // (1) A->B -- Send "p", "g"
    tx.send(Message::Negotiate {
        modulus: NIST_MODULUS.clone(),
        base: NIST_BASE.clone(),
    })
    .unwrap();

    // (2) B->A -- Send ACK
    match rx.recv().unwrap() {
        Message::Accept => {}
        _ => panic!("Expected `Message::Accept` on Alice"),
    };

    // (3) A->B -- Send "A"
    let dh_offer = DHOffer::new_custom(NIST_MODULUS.clone(), &NIST_BASE);

    tx.send(Message::Offer {
        public_key: dh_offer.get_public().clone(),
    })
    .unwrap();

    // (4) B->A -- Send "B"
    let their_public = match rx.recv().unwrap() {
        Message::Response { public_key } => public_key,
        _ => panic!("Expected `Message::Response` on Alice"),
    };

    let session = dh_offer
        .establish(&their_public)
        .expect("Detected an error!");

    let key_material = session.to_key_material::<SHA1>();

    // (5) A->B -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv

    let my_message = crate::gen_random_bytes_between(123, 456);
    let my_iv = crate::gen_random_bytes(AES128::BLOCK_SIZE);
    let my_encrypted_message = CBC::new(&my_iv).encrypt(&AES128, &my_message, &key_material[0..16]);

    tx.send(Message::Message {
        message: my_encrypted_message,
        iv: my_iv,
    })
    .unwrap();

    // (6) B->A -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
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
    // (1) A->B -- Send "p", "g"
    let (modulus, base) = match rx.recv().unwrap() {
        Message::Negotiate { modulus, base } => (modulus, base),
        _ => panic!("Expected `Message::Negotiate` on Bob"),
    };

    // (2) B->A -- Send ACK
    tx.send(Message::Accept).unwrap();

    // (3) A->B -- Send "A"
    let their_public = match rx.recv().unwrap() {
        Message::Offer { public_key } => public_key,
        _ => panic!("Expected `Message::Offer` on Bob"),
    };

    // (4) B->A -- Send "B"
    let dh_offer = DHOffer::new_custom(modulus, &base);

    tx.send(Message::Response {
        public_key: dh_offer.get_public().clone(),
    })
    .unwrap();

    let session = dh_offer
        .establish(&their_public)
        .expect("Detected an error!");

    let key_material = session.to_key_material::<SHA1>();

    // (5) A->B -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    let (their_ecrypted_message, their_iv) = match rx.recv().unwrap() {
        Message::Message { message, iv } => (message, iv),
        _ => panic!("Expected `Message::Message` on Bob"),
    };

    let their_message = CBC::new(&their_iv)
        .decrypt(&AES128, &their_ecrypted_message, &key_material[0..16])
        .unwrap();

    // (6) B->A -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
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

fn eve_g_1(
    alice_tx: SyncSender<Message>,
    alice_rx: Receiver<Message>,
    bob_tx: SyncSender<Message>,
    bob_rx: Receiver<Message>,
) -> Vec<u8> {
    // (1) A->B -- Send "p", "g"
    let (modulus, _base) = match alice_rx.recv().unwrap() {
        Message::Negotiate { modulus, base } => (modulus, base),
        _ => panic!("Expected `Message::Negotiate` on Eve"),
    };

    // (1B) Send g = 1 to Bob instead
    bob_tx
        .send(Message::Negotiate {
            modulus,
            base: BigUint::from(1_usize),
        })
        .unwrap();

    // (2) B->A -- Send ACK
    match bob_rx.recv().unwrap() {
        Message::Accept => {}
        _ => panic!("Expected `Message::Accept` on Eve"),
    };

    // (2B) Relay it to Alice
    alice_tx.send(Message::Accept).unwrap();

    // (3) A->B -- Send "A"
    //     Notice this isn't a regular MITM since we're ignoring Alice's PK
    let _alice_public = match alice_rx.recv().unwrap() {
        Message::Offer { public_key } => public_key,
        _ => panic!("Expected `Message::Offer` on Eve"),
    };

    // (3B) Relay instead "1" to Bob to force his secret to be "1" like Alice's
    //      Is this a HACK? Or intended? I can't see any other way to force both
    //      ends to have the same shared secret.
    bob_tx
        .send(Message::Offer {
            public_key: BigUint::from(1_usize),
        })
        .unwrap();

    // (4) B->A -- Send "B"
    //     Notice this isn't a regular MITM since we're ignoring Bob's PK
    let bob_public = match bob_rx.recv().unwrap() {
        Message::Response { public_key } => public_key,
        _ => panic!("Expected `Message::Response` on Eve"),
    };

    // (4B) Relay it to Alice
    alice_tx
        .send(Message::Response {
            public_key: bob_public,
        })
        .unwrap();

    // (5) A->M -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    let (alice_encrypted_message, alice_iv) = match alice_rx.recv().unwrap() {
        Message::Message { message, iv } => (message, iv),
        _ => panic!("Expected `Message::Message` from Alice on Eve"),
    };

    // (5B) Relay it to Bob
    bob_tx
        .send(Message::Message {
            message: alice_encrypted_message.clone(),
            iv: alice_iv.clone(),
        })
        .unwrap();

    // (6) B->M -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    let (bob_encrypted_message, bob_iv) = match bob_rx.recv().unwrap() {
        Message::Message { message, iv } => (message, iv),
        _ => panic!("Expected `Message::Message` from Bob on Eve"),
    };

    // (6B) Relay it to Alice
    alice_tx
        .send(Message::Message {
            message: bob_encrypted_message.clone(),
            iv: bob_iv.clone(),
        })
        .unwrap();

    // Okay, let's see if your nefarious deeds were successful...
    let expected_key_material = &SHA1::digest(&BigUint::from(1_usize).to_bytes_be())[0..16];

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

fn eve_g_p(
    alice_tx: SyncSender<Message>,
    alice_rx: Receiver<Message>,
    bob_tx: SyncSender<Message>,
    bob_rx: Receiver<Message>,
) -> Vec<u8> {
    // (1) A->B -- Send "p", "g"
    let (modulus, _base) = match alice_rx.recv().unwrap() {
        Message::Negotiate { modulus, base } => (modulus, base),
        _ => panic!("Expected `Message::Negotiate` on Eve"),
    };

    // (1B) Send g = p to Bob instead
    bob_tx
        .send(Message::Negotiate {
            modulus: modulus.clone(),
            base: modulus,
        })
        .unwrap();

    // (2) B->A -- Send ACK
    match bob_rx.recv().unwrap() {
        Message::Accept => {}
        _ => panic!("Expected `Message::Accept` on Eve"),
    };

    // (2B) Relay it to Alice
    alice_tx.send(Message::Accept).unwrap();

    // (3) A->B -- Send "A"
    //     Notice this isn't a regular MITM since we're ignoring Alice's PK
    let _alice_public = match alice_rx.recv().unwrap() {
        Message::Offer { public_key } => public_key,
        _ => panic!("Expected `Message::Offer` on Eve"),
    };

    // (3B) Relay instead "0" to Bob to force his secret to be "0" like Alice's
    //      Is this a HACK? Or intended? I can't see any other way to force both
    //      ends to have the same shared secret.
    bob_tx
        .send(Message::Offer {
            public_key: BigUint::from(0_usize),
        })
        .unwrap();

    // (4) B->A -- Send "B"
    //     Notice this isn't a regular MITM since we're ignoring Bob's PK
    let bob_public = match bob_rx.recv().unwrap() {
        Message::Response { public_key } => public_key,
        _ => panic!("Expected `Message::Response` on Eve"),
    };

    // (4B) Relay it to Alice
    alice_tx
        .send(Message::Response {
            public_key: bob_public,
        })
        .unwrap();

    // (5) A->M -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    let (alice_encrypted_message, alice_iv) = match alice_rx.recv().unwrap() {
        Message::Message { message, iv } => (message, iv),
        _ => panic!("Expected `Message::Message` from Alice on Eve"),
    };

    // (5B) Relay it to Bob
    bob_tx
        .send(Message::Message {
            message: alice_encrypted_message.clone(),
            iv: alice_iv.clone(),
        })
        .unwrap();

    // (6) B->M -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    let (bob_encrypted_message, bob_iv) = match bob_rx.recv().unwrap() {
        Message::Message { message, iv } => (message, iv),
        _ => panic!("Expected `Message::Message` from Bob on Eve"),
    };

    // (6B) Relay it to Alice
    alice_tx
        .send(Message::Message {
            message: bob_encrypted_message.clone(),
            iv: bob_iv.clone(),
        })
        .unwrap();

    // Okay, let's see if your nefarious deeds were successful...
    let expected_key_material = &SHA1::digest(&BigUint::from(0_usize).to_bytes_be())[0..16];

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

// HACK? I don't get this attack :/
//
// In the way the protocol is designed, I can only change `g` for Bob (Alice
// sends `g` and never receives it, for her it's always the real deal). That
// means that the only thing we control by changing `g` is Bob's public key
// (i.e. `B`). At that point, why bother even touching `g`? Just give Alice
// a bogus `B` directly.
//
// That applies to `g = 1` and `g = p`, but it's even worse in this case.
//
// If I give Bob `g` as `(p-1)`, Bob's public key will be:
// - `1` if his private key is even
//   - This means Alice's "shared" secret is `1`
// - `(p-1)` if his private key is odd
//   - Alice's secret is `1` if her private key is even
//   - Alice's secret is `(p-1)` if her private key is odd
//
// Now, how can we make Bob's and Alice's secret match? By feeding Bob a
// bogus private key, that's not even related to `g`. See where this is going?
// At this point this is either a full-blown MITM, or we're not using `g`
// at all and wer'e just playing with `A` and `B`. Weird.
//
// This same attack would work for ANY `g` as far as I can tell :/
fn eve_g_p_minus_1(
    alice_tx: SyncSender<Message>,
    alice_rx: Receiver<Message>,
    bob_tx: SyncSender<Message>,
    bob_rx: Receiver<Message>,
) -> Vec<u8> {
    // (1) A->B -- Send "p", "g"
    let (modulus, _base) = match alice_rx.recv().unwrap() {
        Message::Negotiate { modulus, base } => (modulus, base),
        _ => panic!("Expected `Message::Negotiate` on Eve"),
    };

    // (1B) Send g = (p - 1) to Bob instead
    bob_tx
        .send(Message::Negotiate {
            modulus: modulus.clone(),
            base: modulus - BigUint::from(1_usize),
        })
        .unwrap();

    // (2) B->A -- Send ACK
    match bob_rx.recv().unwrap() {
        Message::Accept => {}
        _ => panic!("Expected `Message::Accept` on Eve"),
    };

    // (2B) Relay it to Alice
    alice_tx.send(Message::Accept).unwrap();

    // (3) A->B -- Send "A"
    let _alice_public = match alice_rx.recv().unwrap() {
        Message::Offer { public_key } => public_key,
        _ => panic!("Expected `Message::Offer` on Eve"),
    };

    // (3B) Relay "1" to Bob (see note above)
    bob_tx
        .send(Message::Offer {
            public_key: BigUint::from(1_usize),
        })
        .unwrap();

    // (4) B->A -- Send "B"
    let _bob_public = match bob_rx.recv().unwrap() {
        Message::Response { public_key } => public_key,
        _ => panic!("Expected `Message::Response` on Eve"),
    };

    // (4B) Relay "1" to Alice (see note above)
    alice_tx
        .send(Message::Response {
            public_key: BigUint::from(1_usize),
        })
        .unwrap();

    // (5) A->M -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    let (alice_encrypted_message, alice_iv) = match alice_rx.recv().unwrap() {
        Message::Message { message, iv } => (message, iv),
        _ => panic!("Expected `Message::Message` from Alice on Eve"),
    };

    // (5B) Relay it to Bob
    bob_tx
        .send(Message::Message {
            message: alice_encrypted_message.clone(),
            iv: alice_iv.clone(),
        })
        .unwrap();

    // (6) B->M -- Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    let (bob_encrypted_message, bob_iv) = match bob_rx.recv().unwrap() {
        Message::Message { message, iv } => (message, iv),
        _ => panic!("Expected `Message::Message` from Bob on Eve"),
    };

    // (6B) Relay it to Alice
    alice_tx
        .send(Message::Message {
            message: bob_encrypted_message.clone(),
            iv: bob_iv.clone(),
        })
        .unwrap();

    // Okay, let's see if your nefarious deeds were successful...
    let expected_key_material = &SHA1::digest(&BigUint::from(1_usize).to_bytes_be())[0..16];

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
fn test_g_1() {
    let (alice_tx, eve_alice_rx) = sync_channel::<Message>(0);
    let (eve_alice_tx, alice_rx) = sync_channel::<Message>(0);
    let (eve_bob_tx, bob_rx) = sync_channel::<Message>(0);
    let (bob_tx, eve_bob_rx) = sync_channel::<Message>(0);

    let alice_thread = thread::spawn(move || alice(alice_tx, alice_rx));
    let bob_thread = thread::spawn(move || bob(bob_tx, bob_rx));
    let eve_thread =
        thread::spawn(move || eve_g_1(eve_alice_tx, eve_alice_rx, eve_bob_tx, eve_bob_rx));

    let alice_message = alice_thread.join().unwrap();
    bob_thread.join().unwrap();
    let eve_message = eve_thread.join().unwrap();

    // Double check
    assert_eq!(alice_message, eve_message);
}

// This test passes if nobody noticed the MITM
#[test]
fn test_g_p() {
    let (alice_tx, eve_alice_rx) = sync_channel::<Message>(0);
    let (eve_alice_tx, alice_rx) = sync_channel::<Message>(0);
    let (eve_bob_tx, bob_rx) = sync_channel::<Message>(0);
    let (bob_tx, eve_bob_rx) = sync_channel::<Message>(0);

    let alice_thread = thread::spawn(move || alice(alice_tx, alice_rx));
    let bob_thread = thread::spawn(move || bob(bob_tx, bob_rx));
    let eve_thread =
        thread::spawn(move || eve_g_p(eve_alice_tx, eve_alice_rx, eve_bob_tx, eve_bob_rx));

    let alice_message = alice_thread.join().unwrap();
    bob_thread.join().unwrap();
    let eve_message = eve_thread.join().unwrap();

    // Double check
    assert_eq!(alice_message, eve_message);
}

// This test passes if nobody noticed the MITM
#[test]
fn test_g_p_minus_1() {
    let (alice_tx, eve_alice_rx) = sync_channel::<Message>(0);
    let (eve_alice_tx, alice_rx) = sync_channel::<Message>(0);
    let (eve_bob_tx, bob_rx) = sync_channel::<Message>(0);
    let (bob_tx, eve_bob_rx) = sync_channel::<Message>(0);

    let alice_thread = thread::spawn(move || alice(alice_tx, alice_rx));
    let bob_thread = thread::spawn(move || bob(bob_tx, bob_rx));
    let eve_thread =
        thread::spawn(move || eve_g_p_minus_1(eve_alice_tx, eve_alice_rx, eve_bob_tx, eve_bob_rx));

    let alice_message = alice_thread.join().unwrap();
    bob_thread.join().unwrap();
    let eve_message = eve_thread.join().unwrap();

    // Double check
    assert_eq!(alice_message, eve_message);
}
