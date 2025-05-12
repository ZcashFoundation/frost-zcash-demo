use std::collections::{BTreeMap, HashMap};
use std::vec;

use frost_ed25519 as frost;

use frost::keys::IdentifierList;
use frost::{aggregate, SigningPackage};
use frostd::SendSigningPackageArgs;
use participant::round2::generate_signature;
use rand::thread_rng;

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
        let (nonce, commitment) = frost::round1::commit(key_packages[&i].signing_share(), &mut rng);
        nonces.insert(*i, nonce);
        commitments.insert(*i, commitment);
    }

    // Coordinator sends message

    let message = "a message".as_bytes().to_vec();

    // Round 2

    let mut signature_shares = BTreeMap::new();

    for participant_identifier in nonces.keys() {
        let config = SendSigningPackageArgs {
            signing_package: vec![SigningPackage::new(commitments.clone(), &message)],
            randomizer: vec![],
            aux_msg: vec![],
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
    let verify_signature = pubkeys.verifying_key().verify(&message, &group_signature);

    assert!(verify_signature.is_ok());
}
