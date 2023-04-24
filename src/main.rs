mod inputs;
#[cfg(test)]
mod tests;
mod trusted_dealer_keygen;

use std::collections::HashMap;
use std::io;

use frost_ed25519 as frost;

use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::Identifier;
use rand::thread_rng;

use crate::inputs::{request_inputs, validate_inputs};
use crate::trusted_dealer_keygen::trusted_dealer_keygen;

fn main() -> io::Result<()> {
    // TODO: error handling
    let config = request_inputs();
    let mut rng = thread_rng();

    let out = validate_inputs(&config);

    match out {
        Ok(_) => (),
        Err(e) => println!("An error occurred: {e}"),
    }

    if out.is_ok() {
        // Print outputs
        let (key_packages, pubkeys) = trusted_dealer_keygen(config, &mut rng);

        print_values(key_packages, pubkeys);
    }

    Ok(())
}

fn print_values(keys: HashMap<Identifier, KeyPackage>, pubkeys: PublicKeyPackage) {
    println!("Group public key: {:x?}", pubkeys.group_public.to_bytes());
    // Need to be able to extract value for VerifiableSecretSharingCommitment that isn't currently accessible
    // println!("Commitment: {:x?}", shares[0].commitment[0]);

    println!("---");

    for (k, v) in keys {
        println!("Participant {:?}", k);
        println!("Secret share: {:x?}", v.secret_share.to_bytes());
        println!("Public key: {:x?}", v.public.to_bytes());
        println!("---")
    }
}
