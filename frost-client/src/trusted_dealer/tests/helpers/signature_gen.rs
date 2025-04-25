use frost::keys::{KeyPackage, SecretShare};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};
use frost_ed25519 as frost;
use rand::rngs::ThreadRng;
use std::collections::BTreeMap;

pub fn key_package(shares: &BTreeMap<Identifier, SecretShare>) -> BTreeMap<Identifier, KeyPackage> {
    let mut key_packages: BTreeMap<_, _> = BTreeMap::new();

    for (identifier, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share.clone()).unwrap();
        key_packages.insert(*identifier, key_package);
    }

    key_packages
}

pub fn round_1(
    min_signers: u16,
    mut rng: &mut ThreadRng,
    key_packages: &BTreeMap<Identifier, KeyPackage>,
) -> (
    BTreeMap<Identifier, SigningNonces>,
    BTreeMap<Identifier, SigningCommitments>,
) {
    // Participant Round 1

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    for participant_index in 1..(min_signers + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let key_package = &key_packages[&participant_identifier];
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }
    (nonces_map, commitments_map)
}

pub fn round_2(
    nonces_map: BTreeMap<Identifier, SigningNonces>,
    key_packages: &BTreeMap<Identifier, KeyPackage>,
    commitments_map: BTreeMap<Identifier, SigningCommitments>,
    message: &[u8],
) -> (SigningPackage, BTreeMap<Identifier, SignatureShare>) {
    let signing_package = frost::SigningPackage::new(commitments_map, message);
    let mut signature_shares = BTreeMap::new();
    for participant_identifier in nonces_map.keys() {
        let key_package = &key_packages[participant_identifier];

        let nonces = &nonces_map[participant_identifier];
        let signature_share = frost::round2::sign(&signing_package, nonces, key_package).unwrap();
        signature_shares.insert(*participant_identifier, signature_share);
    }
    (signing_package, signature_shares)
}
