use std::collections::HashMap;

use frost_ed25519 as frost;

use frost::keys::{PublicKeyPackage, SecretShare};
use frost::Identifier;
use itertools::Itertools;

pub trait Logger {
    fn log(&mut self, value: String);
}

pub fn print_values(
    keys: &HashMap<Identifier, SecretShare>,
    pubkeys: &PublicKeyPackage,
    logger: &mut dyn Logger,
) {
    logger.log(format!(
        "Group public key: {:x?}",
        hex::encode(pubkeys.group_public.to_bytes())
    ));
    // Need to be able to extract value for VerifiableSecretSharingCommitment that isn't currently accessible
    // println!("Commitment: {:x?}", shares[0].commitment[0]);

    println!("---");

    for (k, v) in keys.iter().sorted_by_key(|x| x.0) {
        logger.log(format!("Participant {:?}", k));
        logger.log(format!(
            "Secret share: {:?}",
            hex::encode(v.value.to_bytes())
        ));
        logger.log(format!(
            "Public key: {:?}",
            hex::encode(pubkeys.signer_pubkeys[k].to_bytes())
        ));
        println!("---")
    }
}
