use frost::keys::KeyPackage;
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage, VerifyingKey};
use frost_ed25519 as frost;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use std::collections::HashMap;

use crate::inputs::Config;

pub fn keygen(config: Config) -> Result<Output, frost::Error> {
    let mut rng = thread_rng();
    let max_signers = config.max_signers;
    let min_signers = config.min_signers;
    let (shares, pubkeys) = frost::keys::keygen_with_dealer(max_signers, min_signers, &mut rng)?;

    let key_packages: HashMap<_, _> = shares
        .into_iter()
        .map(|share| Ok((share.identifier, frost::keys::KeyPackage::try_from(share)?)))
        .collect::<Result<_, frost::Error>>()?;

    let (nonces, commitments) = generate_nonces_and_commitments(min_signers, &key_packages, rng);
    let message = "message to sign".as_bytes(); // TODO: choose message
    let comms = commitments.into_values().collect();
    let signing_package = frost::SigningPackage::new(comms, message.to_vec());
    let signature_shares = generate_signature_shares(nonces, &key_packages, &signing_package);
    let group_signature = frost::aggregate(&signing_package, &signature_shares[..], &pubkeys)?;
    let verify_signature = pubkeys.group_public.verify(message, &group_signature);

    let output = Output {
        group_public_key: pubkeys.group_public,
    };

    match verify_signature {
        Ok(_) => Ok(output),
        Err(_) => Err(frost::Error::InvalidSignature), // TODO: Use correct error
    }
}

pub struct Output {
    pub group_public_key: VerifyingKey,
}

fn generate_nonces_and_commitments(
    min_signers: u16,
    key_packages: &HashMap<Identifier, KeyPackage>,
    mut rng: ThreadRng,
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
            &mut rng,
        );
        nonces.insert(participant_identifier, nonce);
        commitments.insert(participant_identifier, commitment);
    }

    (nonces, commitments)
}

fn generate_signature_shares(
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
