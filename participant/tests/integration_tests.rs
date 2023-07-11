use std::collections::{BTreeMap, HashMap};

use frost::keys::IdentifierList;
use frost::{aggregate, SigningPackage};
use frost_ed25519 as frost;
use participant::round1::Round1Config;
use participant::round2::{generate_signature, Round2Config};
use rand::thread_rng;

fn encode_commitment_helper(commitment: Vec<[u8; 32]>) -> String {
    let len_test = commitment.len() as u8;
    let mut out = hex::encode([len_test]);
    for c in commitment {
        out = out + &hex::encode(c)
    }
    out
}

#[test]
fn check_participant() {
    let mut rng = thread_rng();
    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(3, 2, IdentifierList::Default, &mut rng).unwrap();

    let mut key_packages: HashMap<_, _> = HashMap::new();

    for (identifier, secret_share) in &shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share.clone()).unwrap();
        key_packages.insert(identifier, key_package);
    }

    // Round 1

    let mut nonces = HashMap::new();
    let mut commitments = BTreeMap::new();

    for i in shares.keys() {
        let config = Round1Config {
            identifier: *i,
            public_key: pubkeys.signer_pubkeys()[i],
            group_public_key: *pubkeys.group_public(),
            signing_share: *shares[i].secret(),
            vss_commitment: hex::decode(encode_commitment_helper(
                shares[i].commitment().serialize(),
            ))
            .unwrap(),
        };
        let (nonce, commitment) =
            frost::round1::commit(key_packages[&config.identifier].secret_share(), &mut rng);
        nonces.insert(config.identifier, nonce);
        commitments.insert(config.identifier, commitment);
    }

    // Coordinator sends message

    let message = "a message".as_bytes().to_vec();

    // Round 2

    let mut signature_shares = HashMap::new();

    for participant_identifier in nonces.keys() {
        let config = Round2Config {
            message: message.clone(),
            signer_commitments: commitments.clone(),
        };
        let signature = generate_signature(
            config,
            &key_packages[participant_identifier],
            &nonces[participant_identifier],
        )
        .unwrap();
        signature_shares.insert(*participant_identifier, signature);
    }

    // Coordinator aggregates signatures

    let signing_package = SigningPackage::new(commitments, &message);

    let group_signature = aggregate(&signing_package, &signature_shares, &pubkeys).unwrap();
    let verify_signature = pubkeys.group_public().verify(&message, &group_signature);

    assert!(verify_signature.is_ok());
}
