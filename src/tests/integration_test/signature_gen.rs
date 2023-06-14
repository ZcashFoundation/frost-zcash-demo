use frost::keys::{KeyPackage, SecretShare};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};
use frost_ed25519 as frost;
use rand::rngs::ThreadRng;
use std::collections::HashMap;

pub fn generate_key_packages(
    shares: HashMap<Identifier, SecretShare>,
) -> HashMap<Identifier, KeyPackage> {
    let mut key_packages: HashMap<_, _> = HashMap::new();

    for (k, v) in shares {
        let key_package = frost::keys::KeyPackage::try_from(v).unwrap();
        key_packages.insert(k, key_package);
    }
    key_packages
}

pub fn generate_nonces_and_commitments(
    min_signers: u16,
    key_packages: &HashMap<Identifier, KeyPackage>,
    rng: &mut ThreadRng,
) -> (
    HashMap<Identifier, SigningNonces>,
    HashMap<Identifier, SigningCommitments>,
) {
    let mut nonces = HashMap::new();
    let mut commitments = HashMap::new();

    for participant_index in 1..(min_signers + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let (nonce, commitment) = frost::round1::commit(
            participant_identifier,
            key_packages[&participant_identifier].secret_share(),
            rng,
        );
        nonces.insert(participant_identifier, nonce);
        commitments.insert(participant_identifier, commitment);
    }

    (nonces, commitments)
}

pub fn generate_signature_shares(
    nonces: HashMap<Identifier, SigningNonces>,
    key_packages: &HashMap<Identifier, KeyPackage>,
    signing_package: &SigningPackage,
) -> Vec<SignatureShare> {
    let mut signature_shares = Vec::new();

    for participant_identifier in nonces.keys() {
        let key_package = &key_packages[participant_identifier];
        let nonces_to_use = &nonces[participant_identifier];
        let signature_share =
            frost::round2::sign(signing_package, nonces_to_use, key_package).unwrap(); //TODO: handle errors

        signature_shares.push(signature_share);
    }

    signature_shares
}
